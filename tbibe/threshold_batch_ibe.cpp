#include "threshold_batch_ibe.hpp"

#include "mod_arith.hpp"
#include "toy_hash.hpp"

#include <algorithm>
#include <stdexcept>

namespace tbibe {

PartialTrapdoor::PartialTrapdoor(int party, const Matrix& publicC, ThesisSampler& sampler) : party_(party) {
    Matrix tail = sampler.trapdoorGaussianMatrix(KeyCols - Dim, Dim);
    basis_ = Matrix(KeyCols, Vector(Dim));
    for (int i = 0; i < Dim; ++i) basis_[i][i] = 1;
    for (int r = Dim; r < KeyCols; ++r) basis_[r] = tail[r - Dim];

    Matrix R(Dim, Vector(KeyCols - Dim));
    for (int i = 0; i < Dim; ++i) {
        for (int j = 0; j < KeyCols - Dim; ++j) R[i][j] = publicC[i][Dim + j];
    }

    Matrix Rt = ModArith::matMul(R, tail);
    for (int i = 0; i < Dim; ++i) {
        for (int j = 0; j < Dim; ++j) {
            basis_[i][j] = ModArith::sub(i == j ? 1 : 0, Rt[i][j]);
        }
    }
}

Vector PartialTrapdoor::samplePreimage(const Vector& target) const {
    return ModArith::matVec(basis_, target);
}

ThresholdBatchIBE::ThresholdBatchIBE(std::uint64_t seed) : sampler_(seed) {
    publicKey_.Atilde = sampler_.uniformMatrixZq(Dim, IdentityCols);
    publicKey_.Btilde = sampler_.uniformMatrixZq(Dim, IdentityCols);
    publicKey_.C = ToyHash::trapdoorPublicC(sampler_);
    publicKey_.u = sampler_.uniformVectorZq(Dim);
    for (int party = 1; party <= Parties; ++party) authorities_.emplace_back(party, publicKey_.C, sampler_);
}

ThresholdBatchIBE ThresholdBatchIBE::setup(std::uint64_t seed) {
    return ThresholdBatchIBE(seed);
}

Ciphertext ThresholdBatchIBE::encrypt(const std::string& identity, int bit) {
    return encryptBit(identity, bit);
}

Ciphertext ThresholdBatchIBE::encryptBit(const std::string& identity, int bit) {
    validateBit(bit);

    Vector s = sampler_.uniformVectorZq(Dim);
    Scalar e1 = sampler_.errorChi();
    Vector e2 = sampler_.errorVectorChi(KeyCols);
    Vector e3 = sampler_.errorVectorChiPrime(IdentityCols);

    Matrix F = ToyHash::identityMatrixF(identity);
    return {
        identity,
        ModArith::add(ModArith::add(ModArith::dot(publicKey_.u, s), e1), bit ? HalfQ : 0),
        ModArith::addVectors(ModArith::transposeMatVec(publicKey_.C, s), e2),
        ModArith::addVectors(ModArith::transposeMatVec(F, s), e3),
        e1,
        e2,
        e3,
    };
}

std::vector<Ciphertext> ThresholdBatchIBE::encryptBits(
    const std::vector<int>& bits,
    const std::vector<std::string>& identities) {
    validateBatchInput(bits, identities);

    std::vector<Ciphertext> ciphertexts;
    for (std::size_t i = 0; i < bits.size(); ++i) {
        ciphertexts.push_back(encryptBit(identities[i], bits[i]));
    }
    return ciphertexts;
}

PredecryptionShare ThresholdBatchIBE::predecrypt(
    int party,
    const std::vector<int>& thresholdSet,
    const std::vector<std::string>& batchIdentities) const {
    return {party, thresholdSet, batchIdentities, predecryptShare(party, thresholdSet, batchIdentities)};
}

Vector ThresholdBatchIBE::predecryptShare(
    int party,
    const std::vector<int>& thresholdSet,
    const std::vector<std::string>& batchIdentities) const {
    validateThresholdSet(thresholdSet);

    auto it = std::find(thresholdSet.begin(), thresholdSet.end(), party);
    if (it == thresholdSet.end()) throw std::runtime_error("party not in threshold set");

    Vector target = ToyHash::batchTarget(batchIdentities);
    std::vector<Scalar> weights = lagrangeAtZero(thresholdSet);
    Vector preimage = authorities_.at(party - 1).samplePreimage(target);
    return ModArith::scale(weights[it - thresholdSet.begin()], preimage);
}

BatchDecryptionKey ThresholdBatchIBE::combine(const std::vector<PredecryptionShare>& shares) const {
    validateSharesForCombine(shares);

    std::vector<Vector> values;
    for (const auto& share : shares) values.push_back(share.value);
    return {shares.front().thresholdSet, shares.front().batchIdentities, combineShares(values)};
}

Vector ThresholdBatchIBE::combineShares(const std::vector<Vector>& shares) const {
    Vector combined(KeyCols);
    for (const auto& share : shares) combined = ModArith::addVectors(combined, share);
    return combined;
}

Vector ThresholdBatchIBE::batchKey(
    const std::vector<int>& thresholdSet,
    const std::vector<std::string>& batchIdentities) const {
    validateThresholdSet(thresholdSet);

    std::vector<Vector> shares;
    for (int party : thresholdSet) shares.push_back(predecryptShare(party, thresholdSet, batchIdentities));
    return combineShares(shares);
}

Vector ThresholdBatchIBE::identityPreimage(const std::string& identity, const Vector& batchKey) const {
    Vector Cx = ModArith::matVec(publicKey_.C, batchKey);
    Vector residual(Dim);
    for (int i = 0; i < Dim; ++i) residual[i] = ModArith::sub(publicKey_.u[i], Cx[i]);

    Vector v(IdentityCols);
    for (int i = 0; i < Dim; ++i) {
        Scalar diagonal = 1 + ToyHash::u64(identity, i) % (Q - 1);
        Scalar scaled = ModArith::mul(residual[i], ModArith::inverse(diagonal));
        for (int bit = 0; bit < GadgetWidth; ++bit) {
            v[i * GadgetWidth + bit] = (scaled >> bit) & 1;
        }
    }
    return v;
}

int ThresholdBatchIBE::decryptBit(const Ciphertext& ciphertext, const Vector& batchKey) const {
    Vector v = identityPreimage(ciphertext.identity, batchKey);
    Scalar phase = ModArith::sub(ciphertext.c1, ModArith::dot(batchKey, ciphertext.c2));
    phase = ModArith::sub(phase, ModArith::dot(v, ciphertext.c3));
    return (phase > Q / 4 && phase < 3 * Q / 4) ? 1 : 0;
}

int ThresholdBatchIBE::decrypt(const Ciphertext& ciphertext, const BatchDecryptionKey& batchKey) const {
    return decryptBit(ciphertext, batchKey.value);
}

std::vector<int> ThresholdBatchIBE::decryptBatch(
    const std::vector<Ciphertext>& ciphertexts,
    const BatchDecryptionKey& batchKey) const {
    std::vector<int> messages;
    for (const auto& ciphertext : ciphertexts) messages.push_back(decrypt(ciphertext, batchKey));
    return messages;
}

bool ThresholdBatchIBE::decryptionInvariantHolds(const std::string& identity, const Vector& batchKey) const {
    Vector left = ModArith::matVec(publicKey_.C, batchKey);
    Vector right = ModArith::matVec(ToyHash::identityMatrixF(identity), identityPreimage(identity, batchKey));
    return ModArith::addVectors(left, right) == publicKey_.u;
}

void ThresholdBatchIBE::validateBit(int bit) const {
    if (bit != 0 && bit != 1) throw std::invalid_argument("message bit must be 0 or 1");
}

void ThresholdBatchIBE::validateBatchInput(
    const std::vector<int>& bits,
    const std::vector<std::string>& identities) const {
    if (bits.size() != identities.size()) throw std::invalid_argument("bits and identities size mismatch");
    for (int bit : bits) validateBit(bit);
}

void ThresholdBatchIBE::validateThresholdSet(const std::vector<int>& thresholdSet) const {
    if (thresholdSet.size() != Threshold) throw std::invalid_argument("threshold set must have exactly Threshold parties");
    if (!std::is_sorted(thresholdSet.begin(), thresholdSet.end())) throw std::invalid_argument("threshold set must be sorted");
    if (std::adjacent_find(thresholdSet.begin(), thresholdSet.end()) != thresholdSet.end()) {
        throw std::invalid_argument("threshold set contains duplicate parties");
    }
    for (int party : thresholdSet) {
        if (party < 1 || party > Parties) throw std::invalid_argument("party index out of range");
    }
}

void ThresholdBatchIBE::validateSharesForCombine(const std::vector<PredecryptionShare>& shares) const {
    if (shares.size() != Threshold) throw std::invalid_argument("combine needs exactly Threshold shares");
    validateThresholdSet(shares.front().thresholdSet);
    std::vector<int> parties;
    for (const auto& share : shares) {
        if (share.thresholdSet != shares.front().thresholdSet) throw std::invalid_argument("share threshold sets differ");
        if (share.batchIdentities != shares.front().batchIdentities) throw std::invalid_argument("share batches differ");
        if (std::find(share.thresholdSet.begin(), share.thresholdSet.end(), share.party) == share.thresholdSet.end()) {
            throw std::invalid_argument("share party is not in its threshold set");
        }
        parties.push_back(share.party);
    }
    std::sort(parties.begin(), parties.end());
    if (std::adjacent_find(parties.begin(), parties.end()) != parties.end()) {
        throw std::invalid_argument("duplicate pre-decryption share");
    }
}

std::vector<Scalar> ThresholdBatchIBE::lagrangeAtZero(const std::vector<int>& thresholdSet) const {
    std::vector<Scalar> weights;
    for (int xj : thresholdSet) {
        Scalar num = 1;
        Scalar den = 1;
        for (int xh : thresholdSet) {
            if (xh == xj) continue;
            num = ModArith::mul(num, -xh);
            den = ModArith::mul(den, xj - xh);
        }
        weights.push_back(ModArith::mul(num, ModArith::inverse(den)));
    }
    return weights;
}

} // namespace tbibe
