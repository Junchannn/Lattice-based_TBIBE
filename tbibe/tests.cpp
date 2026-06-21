#include "tests.hpp"

#include "mod_arith.hpp"
#include "threshold_batch_ibe.hpp"
#include "toy_hash.hpp"

#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <cstdint>
#include <random>
#include <stdexcept>
#include <string>

namespace tbibe {

class RandomizedTestSuite {
public:
    explicit RandomizedTestSuite(std::uint64_t seed) : rng_(seed) {}

    void run() {
        testSetupProducesWellFormedParameters();
        testChiAndChiPrimeAreActive();
        testEncryptionFeature();
        testPredecryptionAndCombineFeature();
        testSingleDecryptionFeature();
        testBatchDecryptionFeature();
        testValidationErrors();
        testRandomBatchRoundtrips();
        testArbitraryByteRoundtrips();
    }

private:
    std::mt19937_64 rng_;

    static bool inZq(Scalar x) { return 0 <= x && x < Q; }
    static Scalar centered(Scalar x) { x = ModArith::normalize(x); return x > Q / 2 ? x - Q : x; }

    static void assertVectorZq(const Vector& v, std::size_t size) {
        assert(v.size() == size);
        for (Scalar x : v) assert(inZq(x));
    }

    static void assertMatrixZq(const Matrix& m, std::size_t rows, std::size_t cols) {
        assert(m.size() == rows);
        for (const auto& row : m) assertVectorZq(row, cols);
    }

    template <typename Fn>
    static void expectThrows(Fn&& fn) {
        bool thrown = false;
        try {
            fn();
        } catch (const std::invalid_argument&) {
            thrown = true;
        } catch (const std::runtime_error&) {
            thrown = true;
        }
        assert(thrown);
    }

    std::vector<int> randomThresholdSet() {
        std::vector<int> parties{1, 2, 3, 4, 5};
        std::shuffle(parties.begin(), parties.end(), rng_);
        parties.resize(Threshold);
        std::sort(parties.begin(), parties.end());
        return parties;
    }

    std::vector<PredecryptionShare> predecryptAll(
        ThresholdBatchIBE& scheme,
        const std::vector<int>& thresholdSet,
        const std::vector<std::string>& identities) const {
        std::vector<PredecryptionShare> shares;
        for (int party : thresholdSet) shares.push_back(scheme.predecrypt(party, thresholdSet, identities));
        return shares;
    }

    std::vector<int> bitsFromBytes(const std::vector<std::uint8_t>& bytes) const {
        std::vector<int> bits;
        for (std::uint8_t x : bytes) {
            for (int i = 7; i >= 0; --i) bits.push_back((x >> i) & 1);
        }
        return bits;
    }

    std::vector<std::uint8_t> bytesFromBits(const std::vector<int>& bits) const {
        std::vector<std::uint8_t> bytes((bits.size() + 7) / 8);
        for (std::size_t i = 0; i < bits.size(); ++i) {
            bytes[i / 8] |= static_cast<std::uint8_t>(bits[i] << (7 - (i & 7)));
        }
        return bytes;
    }

    Scalar decryptionNoise(const ThresholdBatchIBE& scheme,
                           const Ciphertext& ciphertext,
                           const BatchDecryptionKey& key,
                           int expectedBit) const {
        Vector v = scheme.identityPreimage(ciphertext.identity, key.value);
        Scalar phase = ModArith::sub(ciphertext.c1, ModArith::dot(key.value, ciphertext.c2));
        phase = ModArith::sub(phase, ModArith::dot(v, ciphertext.c3));
        return centered(ModArith::sub(phase, expectedBit ? HalfQ : 0));
    }

    void testSetupProducesWellFormedParameters() {
        ThresholdBatchIBE scheme = ThresholdBatchIBE::setup(11);
        const PublicKey& pk = scheme.publicKey();

        assertMatrixZq(pk.Atilde, Dim, IdentityCols);
        assertMatrixZq(pk.Btilde, Dim, IdentityCols);
        assertMatrixZq(pk.C, Dim, KeyCols);
        assertVectorZq(pk.u, Dim);
    }

    void testChiAndChiPrimeAreActive() {
        ThresholdBatchIBE scheme = ThresholdBatchIBE::setup(12);
        bool sawChi = false;
        bool sawChiPrime = false;

        for (int i = 0; i < 200; ++i) {
            Ciphertext ct = scheme.encrypt("noise:" + std::to_string(i), i & 1);
            sawChi = sawChi || ct.e1 != 0 || std::any_of(ct.e2.begin(), ct.e2.end(), [](Scalar x) { return x != 0; });
            sawChiPrime = sawChiPrime || std::any_of(ct.e3.begin(), ct.e3.end(), [](Scalar x) { return x != 0; });
        }

        assert(sawChi);
        assert(sawChiPrime);
    }

    void testEncryptionFeature() {
        ThresholdBatchIBE scheme = ThresholdBatchIBE::setup(17);
        Ciphertext ct0 = scheme.encrypt("alice@example", 0);
        Ciphertext ct1 = scheme.encrypt("alice@example", 1);

        assert(ct0.identity == "alice@example");
        assert(ct1.identity == "alice@example");
        assertVectorZq(ct0.c2, KeyCols);
        assertVectorZq(ct0.c3, IdentityCols);
        assertVectorZq(ct1.c2, KeyCols);
        assertVectorZq(ct1.c3, IdentityCols);
        assertVectorZq(ct0.e2, KeyCols);
        assertVectorZq(ct0.e3, IdentityCols);
        assert(inZq(ct0.c1));
        assert(inZq(ct1.c1));
    }

    void testPredecryptionAndCombineFeature() {
        ThresholdBatchIBE scheme = ThresholdBatchIBE::setup(13);
        std::vector<std::string> identities{"id:a", "id:b", "id:c"};
        std::vector<int> thresholdSet{1, 3, 5};

        auto shares = predecryptAll(scheme, thresholdSet, identities);
        for (std::size_t i = 0; i < shares.size(); ++i) {
            assert(shares[i].party == thresholdSet[i]);
            assert(shares[i].thresholdSet == thresholdSet);
            assert(shares[i].batchIdentities == identities);
            assertVectorZq(shares[i].value, KeyCols);
        }

        BatchDecryptionKey key = scheme.combine(shares);
        assert(key.thresholdSet == thresholdSet);
        assert(key.batchIdentities == identities);
        assert(ModArith::matVec(scheme.publicKey().C, key.value) == ToyHash::batchTarget(identities));
    }

    void testSingleDecryptionFeature() {
        ThresholdBatchIBE scheme = ThresholdBatchIBE::setup(14);
        std::vector<std::string> identities{"id:single"};
        std::vector<int> thresholdSet{1, 2, 4};
        BatchDecryptionKey key = scheme.combine(predecryptAll(scheme, thresholdSet, identities));

        Ciphertext zero = scheme.encrypt(identities[0], 0);
        Ciphertext one = scheme.encrypt(identities[0], 1);

        assert(scheme.decryptionInvariantHolds(identities[0], key.value));
        assert(std::llabs(decryptionNoise(scheme, zero, key, 0)) < Q / 4);
        assert(std::llabs(decryptionNoise(scheme, one, key, 1)) < Q / 4);
        assert(scheme.decrypt(zero, key) == 0);
        assert(scheme.decrypt(one, key) == 1);
    }

    void testBatchDecryptionFeature() {
        ThresholdBatchIBE scheme = ThresholdBatchIBE::setup(15);
        std::vector<std::string> identities{"tx:0", "tx:1", "tx:2", "tx:3", "tx:4"};
        std::vector<int> bits{0, 1, 1, 0, 1};
        std::vector<int> thresholdSet{2, 3, 5};

        BatchDecryptionKey key = scheme.combine(predecryptAll(scheme, thresholdSet, identities));
        std::vector<Ciphertext> ciphertexts = scheme.encryptBits(bits, identities);
        for (std::size_t i = 0; i < bits.size(); ++i) {
            assert(std::llabs(decryptionNoise(scheme, ciphertexts[i], key, bits[i])) < Q / 4);
        }
        assert(scheme.decryptBatch(ciphertexts, key) == bits);
    }

    void testValidationErrors() {
        ThresholdBatchIBE scheme = ThresholdBatchIBE::setup(16);
        std::vector<std::string> identities{"id:0", "id:1"};
        std::vector<int> thresholdSet{1, 2, 3};

        expectThrows([&] { scheme.encrypt("bad-bit", 2); });
        expectThrows([&] { scheme.encryptBits({0, 1}, {"only-one-id"}); });
        expectThrows([&] { scheme.predecrypt(4, thresholdSet, identities); });
        expectThrows([&] { scheme.predecrypt(1, {1, 1, 3}, identities); });
        expectThrows([&] { scheme.predecrypt(1, {3, 1, 2}, identities); });

        auto shares = predecryptAll(scheme, thresholdSet, identities);
        shares[1].batchIdentities = {"different"};
        expectThrows([&] { scheme.combine(shares); });
    }

    void testRandomBatchRoundtrips() {
        for (int tc = 0; tc < 10; ++tc) {
            ThresholdBatchIBE scheme = ThresholdBatchIBE::setup(rng_());
            int batchSize = 1 + (rng_() % 40);
            std::vector<int> bits(batchSize);
            std::vector<std::string> identities(batchSize);

            for (int i = 0; i < batchSize; ++i) {
                bits[i] = rng_() & 1;
                identities[i] = "id:" + std::to_string(tc) + ":" + std::to_string(i) + ":" + std::to_string(rng_());
            }

            auto thresholdSet = randomThresholdSet();
            BatchDecryptionKey key = scheme.combine(predecryptAll(scheme, thresholdSet, identities));
            assert(ModArith::matVec(scheme.publicKey().C, key.value) == ToyHash::batchTarget(identities));

            auto ciphertexts = scheme.encryptBits(bits, identities);
            for (int i = 0; i < batchSize; ++i) {
                assert(scheme.decryptionInvariantHolds(identities[i], key.value));
                assert(std::llabs(decryptionNoise(scheme, ciphertexts[i], key, bits[i])) < Q / 4);
                assert(scheme.decrypt(ciphertexts[i], key) == bits[i]);
            }
            assert(scheme.decryptBatch(ciphertexts, key) == bits);
        }
    }

    void testArbitraryByteRoundtrips() {
        for (int tc = 0; tc < 10; ++tc) {
            ThresholdBatchIBE scheme = ThresholdBatchIBE::setup(rng_());
            int len = rng_() % 128;
            std::vector<std::uint8_t> msg(len);
            for (auto& x : msg) x = static_cast<std::uint8_t>(rng_());

            auto bits = bitsFromBytes(msg);
            std::vector<std::string> identities(bits.size());
            for (std::size_t i = 0; i < identities.size(); ++i) {
                identities[i] = "byte:" + std::to_string(tc) + ":" + std::to_string(i);
            }

            auto thresholdSet = randomThresholdSet();
            BatchDecryptionKey key = scheme.combine(predecryptAll(scheme, thresholdSet, identities));
            auto ciphertexts = scheme.encryptBits(bits, identities);
            assert(bytesFromBits(scheme.decryptBatch(ciphertexts, key)) == msg);
        }
    }
};

void runRandomizedTests() {
    RandomizedTestSuite(7).run();
}

} // namespace tbibe
