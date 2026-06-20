#pragma once

// Compact FIPS-202 Keccak-1600 (XKCP "more-compact" variant).
// Source: https://github.com/XKCP/XKCP  (CC0 / public domain)
// Vendored verbatim in keccak.cpp; only the two functions we use are exposed.

#include <cstddef>
#include <cstdint>

namespace tbibe {

// Extendable-output function: SHAKE-256.
// Produces exactly `outLen` bytes into `out`.
void shake256(const uint8_t *in, std::size_t inLen,
              uint8_t *out, std::size_t outLen);

// Convenience: squeeze one little-endian uint64_t from
//   SHAKE-256( domain_tag (8 B) || input )
// `tag` acts as a domain separator.
uint64_t shake256_u64(const uint8_t *in, std::size_t inLen, uint64_t tag);

} // namespace tbibe
