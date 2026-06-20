#pragma once

#include "config.hpp"
#include "thesis_sampler.hpp"

namespace tbibe {

class PartialTrapdoor {
public:
    PartialTrapdoor(int party, const Matrix& publicC, ThesisSampler& sampler);

    int party() const { return party_; }
    Vector samplePreimage(const Vector& target) const;

private:
    int party_;
    Matrix basis_;
};

class ThresholdBatchIBE {
public:
    explicit ThresholdBatchIBE(std::uint64_t seed = 1);
    static ThresholdBatchIBE setup(std::uint64_t seed = 1);

    const PublicKey& publicKey() const { return publicKey_; }

    Ciphertext encrypt(const std::string& identity, int bit);
    PredecryptionShare predecrypt(int party,
                                  const std::vector<int>& thresholdSet,
                                  const std::vector<std::string>& batchIdentities) const;
    BatchDecryptionKey combine(const std::vector<PredecryptionShare>& shares) const;
    int decrypt(const Ciphertext& ciphertext, const BatchDecryptionKey& batchKey) const;
    std::vector<int> decryptBatch(const std::vector<Ciphertext>& ciphertexts,
                                  const BatchDecryptionKey& batchKey) const;

    Ciphertext encryptBit(const std::string& identity, int bit);
    std::vector<Ciphertext> encryptBits(const std::vector<int>& bits,
                                        const std::vector<std::string>& identities);

    Vector predecryptShare(int party,
                           const std::vector<int>& thresholdSet,
                           const std::vector<std::string>& batchIdentities) const;
    Vector combineShares(const std::vector<Vector>& shares) const;
    Vector batchKey(const std::vector<int>& thresholdSet,
                    const std::vector<std::string>& batchIdentities) const;

    Vector identityPreimage(const std::string& identity, const Vector& batchKey) const;
    int decryptBit(const Ciphertext& ciphertext, const Vector& batchKey) const;
    bool decryptionInvariantHolds(const std::string& identity, const Vector& batchKey) const;

private:
    PublicKey publicKey_;
    std::vector<PartialTrapdoor> authorities_;
    ThesisSampler sampler_;

    void validateBit(int bit) const;
    void validateBatchInput(const std::vector<int>& bits,
                            const std::vector<std::string>& identities) const;
    void validateThresholdSet(const std::vector<int>& thresholdSet) const;
    void validateSharesForCombine(const std::vector<PredecryptionShare>& shares) const;
    std::vector<Scalar> lagrangeAtZero(const std::vector<int>& thresholdSet) const;
};

} // namespace tbibe
