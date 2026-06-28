# Lattice-based Threshold Batch IBE (TBIBE)

A C++17 proof-of-concept implementation of **Threshold Batch Identity-Based Encryption** built on integer k-LWE lattice hardness assumptions for a graduation thesis.

## Scheme Overview

TBIBE allows a committee of `N` parties to jointly decrypt a batch of ciphertexts encrypted to distinct identities, using threshold secret sharing: any `k` of `N` parties can collaborate to produce a **batch decryption key** without any single party learning the full secret.

**Protocol phases:**

| Phase | Algorithm | Description |
|---|---|---|
| Key generation | `Setup(seed)` | Generates public key and distributes partial trapdoor shares to each party |
| Encryption | `Enc(pk, id, bit)` | Encrypts a single bit under an identity string |
| Pre-decryption | `PreDec(sk_j, T, ids)` | Each party `j ∈ T` produces a partial decryption share for the batch |
| Combination | `Combine(shares)` | Aggregates `k` shares via Lagrange interpolation into a batch decryption key |
| Decryption | `Dec(ct, bdk)` | Recovers plaintext from a ciphertext using the combined batch decryption key |

## Parameters

| Parameter | Value | Notes |
|---|---|---|
| Modulus `q` | 12289 | Prime; gadget width `⌈log₂ q⌉ = 14` |
| LWE dimension `n` | 448 | Chosen for ~135-bit security |
| Threshold `k` | 3 | Minimum parties required to decrypt |
| Parties `N` | 5 | Total committee size |
| Error std. dev. `σ` | 3.2 | Discrete Gaussian parameter |
| Batch size | 5 | Identities per decryption batch |

**Security:** The binding constraint comes from the largest ciphertext component c₃ (dimension m = 14n = 6272). Primal uSVP attack gives ~134.7 bits; dual hybrid gives ~139.3 bits. Combined security ≈ 2^135.

## Ciphertext Structure

Each ciphertext `(c1, c2, c3)` has three components:

- **c₁** — scalar in Z_q; encodes the message bit scaled by q/2
- **c₂** — vector of length 2n = 896; LWE encryption component
- **c₃** — vector of length 14n = 6272; gadget-based identity binding

## Benchmark Results

Measured on an x86-64 machine (500 reps for Setup/PreDec, 2000 reps for Enc/Combine/Dec), batch size = 5, threshold set size = 3.

### Communication and Key Sizes

| Object | Size |
|---|---|
| Public key `|pk|` | 10,290.8 KB |
| Ciphertext `|ct|` | 12.3 KB |
| Per-party pre-dec share `|sbk_j|` | 1.5 KB |
| Combined batch decryption key `|sbk|` | 1.5 KB |
| Per-party secret key `|sk_j|` | 686.0 KB |
| Pre-dec communication (per party) | 1.5 KB |
| Total committee communication (per batch) | 4.6 KB |

### Operation Timings

| Operation | Mean Time | Notes |
|---|---|---|
| Setup | 2370.8 ms | One-time key generation |
| Enc (per message) | 32.5 ms | Single-bit encryption |
| PreDec (per party) | 8.8 ms | Per-party partial decryption |
| — SampleLeft (target expansion) | 6.8 ms | Identity hashing + batch target |
| — PSampPre (preimage + scale) | 2.0 ms | Lagrange-weighted preimage sampling |
| Combine | 4.78 µs | Lagrange interpolation of shares |
| Dec (per ciphertext) | 9.0 ms | Single ciphertext decryption |

All timings are unoptimized (no NTT, no SIMD) — this is a proof-of-concept implementation.

## Building and Running

Requires a C++17 compiler and standard library.

```bash
# Build
make

# Run correctness tests
make test

# Run benchmarks
make bench

# Build with AddressSanitizer + UBSan
make asan

# Remove generated binaries
make clean
```

## Project Structure

```
.
├── .gitignore                         # Local build artifacts and ignored thesis files
├── README.md                          # Project overview, parameters, and usage notes
├── Makefile                           # Build, test, benchmark, sanitizer, and clean targets
├── kLWE_estimate.sage                 # Sage script for k-LWE security estimation
├── tbibe_poc.cpp                      # CLI entry point: ./tbibe_poc [bench]
├── tbibe/                             # C++17 TBIBE proof-of-concept implementation
│   ├── config.hpp                     # Scheme parameters and core data structures
│   ├── threshold_batch_ibe.{hpp,cpp}  # Setup, Enc, PreDec, Combine, and Dec
│   ├── thesis_sampler.{hpp,cpp}      # Discrete Gaussian and uniform samplers
│   ├── mod_arith.{hpp,cpp}           # Modular arithmetic and matrix/vector routines
│   ├── hash.{hpp,cpp}                # Identity-to-matrix hashing
│   ├── keccak.{hpp,cpp}              # SHAKE-256 pseudorandom expansion
│   ├── bench.{hpp,cpp}               # Timing and size benchmarks
│   └── tests.{hpp,cpp}               # Randomized correctness tests
```

## Security Notes

This is a **research prototype** — not for production use. Specific limitations:

- Trapdoor sampling uses simplified discrete Gaussian (bounded uniform fallback)
- No constant-time arithmetic; vulnerable to timing side-channels
- Public key is uncompressed; real deployment would use seed-expandable matrices

## License

MIT
