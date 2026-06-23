// hash.cpp — hash oracles backed by SHAKE-256 (Keccak-1600).
//
// All three hash functions H, H_ro, H_sp from the BTD construction are
// modelled here as domain-separated SHAKE-256 evaluations.
//
// Domain tags (64-bit constants) ensure the three oracles are independent:
//   H     : tag 0x01 — identity string → {0,1}^d
//   H_ro  : tag 0x02 — identity string → Z_q^{nk × m_bar}  (public matrix)
//   H_sp  : tag 0x03 — serialised (A, T_A, ids, u, σ) → random coins
//   batch : tag 0x04 — packed identity list → Z_q^n          (target vector)

#include "hash.hpp"
#include "keccak.hpp"

#include <cstring>
#include <cstdint>

namespace tbibe {

// ── Internal: squeeze one uniform uint64_t from SHAKE-256 ────────────────
//
// shake256_u64(data, len, tag) absorbs (tag || data) and squeezes 8 bytes.
// This replaces the old FNV-1a/splitmix `u64` + `mix` pair.

static uint64_t h_u64(const std::string& input, uint64_t tag)
{
    return shake256_u64(
        reinterpret_cast<const uint8_t*>(input.data()),
        input.size(),
        tag);
}

// ── Hash::u64 (public API, kept for the test suite) ──────────────────────

uint64_t Hash::u64(const std::string& input, uint64_t seed)
{
    // seed is used as the domain tag so callers stay compatible.
    return h_u64(input, seed);
}

// ── H: identity → {0,1}^d (d = 1 in the toy instantiation) ───────────────
//
// We squeeze 1 byte and take its LSB. The tag 0x01 is the domain separator
// for H; the index `i` is mixed into the tag so each output bit is
// independent.

// (No separate exported function; identityMatrixF calls h_u64 with tag
//  0x0100 | col_index, consistent with the "H_ro" semantics below.)

// ── H_ro: identity → Z_q^{nk × m_bar}  (random oracle output matrix) ────
//
// In the toy PoC the F_r matrix is built as a diagonal: column (i*W + bit)
// gets the value  diagonal_i * 2^bit mod Q, where diagonal_i is derived by
// squeezing from SHAKE-256(H_ro_domain || identity)[i].  This preserves the
// gadget decomposition structure that identityPreimage exploits, while
// sourcing the diagonal values from a proper cryptographic hash.

Matrix Hash::identityMatrixF(const std::string& identity)
{
    // Domain tags 0, 1, …, Dim-1 must match the seeds passed by
    // ThresholdBatchIBE::identityPreimage, which calls Hash::u64(identity, i).
    // Hash::u64 delegates directly to h_u64(input, seed), so using tag = i
    // here keeps the two functions consistent (F-matrix and its inverse).

    Matrix F(Dim, Vector(IdentityCols, 0));
    for (int i = 0; i < Dim; ++i) {
        // Same SHAKE-256 call as Hash::u64(identity, i).
        uint64_t raw = h_u64(identity, static_cast<uint64_t>(i));
        Scalar diagonal = 1 + static_cast<Scalar>(raw % static_cast<uint64_t>(Q - 1));

        // Gadget decomposition: F[i][i*W + bit] = diagonal * 2^bit mod Q.
        Scalar power = 1;
        for (int bit = 0; bit < GadgetWidth; ++bit) {
            F[i][i * GadgetWidth + bit] = diagonal * power % Q;
            power = power * 2 % Q;
        }
    }
    return F;
}

// ── Batch target: packed identity list → Z_q^n ───────────────────────────
//
// Models H_sp / batch target derivation.  We null-separate the identities
// and squeeze one uint64_t per coordinate from SHAKE-256.

Vector Hash::batchTarget(const std::vector<std::string>& identities)
{
    constexpr uint64_t BATCH_BASE = 0x0400ULL;

    // Pack: identity_0 \0 identity_1 \0 … identity_{ℓ-1} \0
    std::string packed;
    packed.reserve(identities.size() * 8);
    for (const auto& id : identities) { packed += id; packed += '\0'; }

    Vector target(Dim);
    for (int i = 0; i < Dim; ++i) {
        uint64_t raw = h_u64(packed, BATCH_BASE | static_cast<uint64_t>(i));
        // Map to {-1, 0, 1} ⊂ Z_q: raw mod 3 gives 0,1,2 → shift by 1.
        Scalar x = static_cast<Scalar>(raw % 3) - 1;
        target[i] = (x < 0) ? Q + x : x;
    }
    return target;
}

// ── trapdoorPublicC: generate (toy) public trapdoor matrix C ──────────────
//
// In the formal scheme C comes from TrapGen.  In the toy PoC we use the
// identity matrix (zero-noise trapdoor) regardless of the hash function, so
// that partial-trapdoor arithmetic stays exact.  Only the randomness source
// for row/column scalars outside the toy-trapdoor basis would use SHAKE-256
// in a fuller implementation; nothing changes here.

Matrix Hash::trapdoorPublicC(ThesisSampler& /*sampler*/)
{
    Matrix C(Dim, Vector(KeyCols, 0));
    for (int i = 0; i < Dim; ++i) C[i][i] = 1;
    return C;
}

} // namespace tbibe
