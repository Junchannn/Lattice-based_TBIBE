#include "bench.hpp"

#include "config.hpp"
#include "mod_arith.hpp"
#include "threshold_batch_ibe.hpp"
#include "hash.hpp"

#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace tbibe {

using Clock = std::chrono::steady_clock;
using Us    = std::chrono::duration<double, std::micro>;

static double elapsed_us(Clock::time_point a, Clock::time_point b) {
    return std::chrono::duration_cast<Us>(b - a).count();
}

template <typename Fn>
static double meanUs(Fn&& fn, int reps) {
    auto t0 = Clock::now();
    for (int i = 0; i < reps; ++i) fn();
    auto t1 = Clock::now();
    return elapsed_us(t0, t1) / reps;
}

static std::string fmtSize(std::size_t bytes) {
    std::ostringstream os;
    if (bytes < 1024) {
        os << bytes << " B (" << std::fixed << std::setprecision(3)
           << bytes / 1024.0 << " KB)";
    } else {
        os << std::fixed << std::setprecision(1) << bytes / 1024.0 << " KB";
    }
    return os.str();
}

static std::string fmtTime(double us) {
    std::ostringstream os;
    if (us < 1000.0) {
        os << std::fixed << std::setprecision(2) << us << " µs";
    } else {
        os << std::fixed << std::setprecision(3) << us / 1000.0 << " ms";
    }
    return os.str();
}

static void row(const std::string& metric, const std::string& unit, const std::string& val) {
    std::cout << "  " << std::left << std::setw(48) << metric
              << std::setw(6) << unit << val << "\n";
}

// Compute sizes in bits, then convert to bytes (bit-packed).
static std::size_t matrixBits(const Matrix& M) {
    if (M.empty() || M[0].empty()) return 0;
    // Each entry is in Z_q, q = 12289 < 2^14, so 14 bits per scalar.
    constexpr int bitsPerScalar = 14;
    return M.size() * M[0].size() * bitsPerScalar;
}

static std::size_t vectorBits(const Vector& v) {
    constexpr int bitsPerScalar = 14;
    return v.size() * bitsPerScalar;
}

static std::size_t pkSizeBytes(const PublicKey& pk) {
    std::size_t bits = matrixBits(pk.C)
                     + matrixBits(pk.Atilde)
                     + matrixBits(pk.Btilde)
                     + vectorBits(pk.u);
    return (bits + 7) / 8;
}

static std::size_t ctSizeBytes(const Ciphertext& ct) {
    constexpr int bitsPerScalar = 14;
    std::size_t bits = bitsPerScalar                      // c1
                     + vectorBits(ct.c2)
                     + vectorBits(ct.c3);
    return (bits + 7) / 8 + ct.identity.size() + 1;
}

static std::size_t vecSizeBytes(const Vector& v) {
    return (vectorBits(v) + 7) / 8;
}

// Partial trapdoor basis is KeyCols × Dim scalars (the basis_ matrix).
static std::size_t skjBytes() {
    constexpr int bitsPerScalar = 14;
    return (static_cast<std::size_t>(KeyCols) * Dim * bitsPerScalar + 7) / 8;
}

void runBenchmarks() {
    constexpr int BATCH       = 5;
    constexpr int REPS_SLOW   = 500;
    constexpr int REPS_FAST   = 2000;

    std::vector<std::string> ids;
    for (int i = 0; i < BATCH; ++i)
        ids.push_back("tx:" + std::to_string(i));

    std::vector<int> bits       = {0, 1, 1, 0, 1};
    std::vector<int> T          = {1, 3, 5};  // threshold set of size k=3

    // ---------- Setup ----------
    ThresholdBatchIBE scheme = ThresholdBatchIBE::setup(42);
    double setupUs = meanUs([&]{ ThresholdBatchIBE::setup(42); }, REPS_SLOW);

    // ---------- Enc ----------
    double encUs = meanUs([&]{ scheme.encryptBit(ids[0], 1); }, REPS_FAST);
    Ciphertext sct = scheme.encryptBit(ids[0], 1);

    // ---------- PreDec ----------
    // Total PreDec time per party.
    double predecUs = meanUs([&]{
        for (int p : T) scheme.predecrypt(p, T, ids);
    }, REPS_SLOW) / static_cast<double>(T.size());

    // "SampleLeft" analogue: batch target derivation (Expand phase).
    // In the toy PoC this corresponds to batchTarget() which hashes the
    // identity list into the target vector u_hat = (u,...,u).
    double sampleLeftUs = meanUs([&]{
        Hash::batchTarget(ids);
    }, REPS_FAST);

    // "PSampPre" analogue: the Lagrange-weighted partial preimage step.
    // This is the remainder of PreDec time after target derivation.
    double psampUs = predecUs - sampleLeftUs;
    if (psampUs < 0.0) psampUs = 0.0;

    // ---------- Combine ----------
    std::vector<PredecryptionShare> shares;
    for (int p : T) shares.push_back(scheme.predecrypt(p, T, ids));

    double combineUs = meanUs([&]{ scheme.combine(shares); }, REPS_FAST);
    BatchDecryptionKey bdk = scheme.combine(shares);

    // ---------- Dec ----------
    auto cts = scheme.encryptBits(bits, ids);
    double decUs = meanUs([&]{
        for (const auto& ct : cts) scheme.decrypt(ct, bdk);
    }, REPS_FAST) / static_cast<double>(cts.size());

    // ---------- Sizes ----------
    std::size_t pk_B   = pkSizeBytes(scheme.publicKey());
    std::size_t ct_B   = ctSizeBytes(sct);
    std::size_t sbkj_B = vecSizeBytes(shares[0].value);
    std::size_t sbk_B  = vecSizeBytes(bdk.value);
    std::size_t sk_B   = skjBytes();
    std::size_t comm_B = sbkj_B;                        // per-party upload
    std::size_t total_B = comm_B * T.size();            // total committee

    // ---------- Report ----------
    std::cout << "\n";
    std::cout << "========================================================\n";
    std::cout << "  BTD Toy-PoC Benchmark\n";
    std::cout << "  Q=" << Q << "  n=" << Dim
              << "  k=" << Threshold << "  N=" << Parties
              << "  batch=" << BATCH << "\n";
    std::cout << "========================================================\n\n";

    std::cout << "  [Sizes]\n";
    row("Public-key size |pk|",                     "size", fmtSize(pk_B));
    row("Ciphertext size |ct|",                     "size", fmtSize(ct_B));
    row("Per-party pre-dec key |sbk_j|",            "size", fmtSize(sbkj_B));
    row("Combined pre-dec key |sbk|",               "size", fmtSize(sbk_B));
    row("Per-party secret key |sk_j|",              "size", fmtSize(sk_B));
    row("Pre-dec communication (per party)",        "size", fmtSize(comm_B));
    row("Total committee communication (per batch)","size", fmtSize(total_B));

    std::cout << "\n  [Timings — mean over " << REPS_SLOW << "/" << REPS_FAST << " reps]\n";
    row("Setup time",                               "time", fmtTime(setupUs));
    row("Enc time (per message)",                   "time", fmtTime(encUs));
    row("PreDec time (per party)",                  "time", fmtTime(predecUs));
    row("  of which SampleLeft (Expand + target)",  "time", fmtTime(sampleLeftUs));
    row("  of which PSampPre (preimage + scale)",   "time", fmtTime(psampUs));
    row("Combine time",                             "time", fmtTime(combineUs));
    row("Dec time (per ciphertext)",                "time", fmtTime(decUs));

    std::cout << "\n========================================================\n\n";
}

} // namespace tbibe
