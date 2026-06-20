"""
Concrete parameter selection for TBIBE scheme (ALLW25-based kappa-LWE).

Key insight from Table 4.1:
  - chi_0  = LWE indistinguishability error (small, drives kappa-LWE security)
  - sigma_2 = PSampPre Gaussian width (large, drives correctness bound)
  These are DECOUPLED: chi_0 can be small while sigma_2 is large.

Security   is determined by: (n_eff = nk, q, chi_0, m_total)
Correctness is determined by: q > 4 * sigma_2 * sqrt(m)  [separate analysis]

This script focuses on the security side: sweep (n, log2q) and estimate kappa-LWE hardness.
"""

import estimator as est
from estimator import *
from math import log2, ceil, sqrt

# ─── Fixed choices ────────────────────────────────────────────────
lam   = 128       # target security level
k     = 3         # threshold
N     = 5         # parties
chi_0 = 3.2       # LWE error std dev (chi_0 in Table 4.1, indistinguishability assumption)

def derive_m(n_eff, log2q):
    """m >= 2 * n_eff * log2(q) for trapdoor generation."""
    return int(ceil(2 * n_eff * log2q / n_eff) * n_eff)

def total_samples(n, log2q):
    """Total samples the adversary sees in kappa-LWE."""
    n_eff   = n * k
    m       = derive_m(n_eff, log2q)
    m_main  = 2 * m * k            # = 2mk
    m_hints = 2 * m * (k - 1)      # = 2m(k-1) partial trapdoor columns
    return m_main + m_hints         # = 2m(2k-1)

def security_bits(n, log2q):
    n_eff = n * k
    q     = 2**log2q
    m_tot = total_samples(n, log2q)
    params = LWE.Parameters(
        n  = n_eff,
        q  = q,
        Xs = ND.UniformMod(q),
        Xe = ND.DiscreteGaussian(chi_0),
        m  = m_tot,
    )
    try:
        res = LWE.estimate(params, jobs=4, deny_list=("arora-gb",), quiet=True)
        return min(float(log2(v["rop"])) for v in res.values() if "rop" in v)
    except Exception:
        return float("inf")

def hint_impact(n, log2q):
    """Compare security with and without kappa hints."""
    n_eff   = n * k
    q       = 2**log2q
    m       = derive_m(n_eff, log2q)
    m_main  = 2 * m * k
    m_total = m_main + 2 * m * (k - 1)

    def bits(m_val):
        p = LWE.Parameters(n=n_eff, q=q,
                           Xs=ND.UniformMod(q),
                           Xe=ND.DiscreteGaussian(chi_0),
                           m=m_val)
        try:
            r = LWE.estimate(p, jobs=4, deny_list=("arora-gb",), quiet=True)
            return min(float(log2(v["rop"])) for v in r.values() if "rop" in v)
        except: return float("inf")

    return bits(m_main), bits(m_total)

# ─── Sweep over n and log2(q) ────────────────────────────────────
n_values   = [128, 256, 512]
log2q_range = range(10, 36)

print("=" * 75)
print(f"kappa-LWE Security Sweep  [k={k}, chi_0={chi_0}, target={lam} bits]")
print("=" * 75)

best = {}   # n -> (log2q, bits) best choice

for n in n_values:
    n_eff = n * k
    print(f"\n--- n={n}, n_eff=nk={n_eff} ---")
    print(f"{'log2(q)':>8} {'m':>8} {'m_total':>9} {'bits':>7}  status")
    print("-" * 50)

    for lq in log2q_range:
        m     = derive_m(n_eff, lq)
        m_tot = total_samples(n, lq)
        bits  = security_bits(n, lq)
        ok    = bits >= lam
        flag  = " <-- MEETS TARGET" if ok else ""
        print(f"{lq:>8} {m:>8} {m_tot:>9} {bits:>7.1f}  {'OK' if ok else '--'}{flag}")
        if ok and n not in best:
            best[n] = (lq, m, m_tot, bits)

# ─── Best configs summary ─────────────────────────────────────────
print()
print("=" * 75)
print("SUMMARY: Smallest log2(q) meeting the 128-bit target per n")
print("=" * 75)
print(f"\n{'n':>5} {'n_eff':>6} {'log2(q)':>8} {'alpha=chi/q':>12} {'m':>8} {'m_total':>9} {'bits':>7}")
print("-" * 65)

for n, (lq, m, m_tot, bits) in sorted(best.items()):
    n_eff = n * k
    alpha = chi_0 / (2**lq)
    print(f"{n:>5} {n_eff:>6} {lq:>8} {alpha:>12.2e} {m:>8} {m_tot:>9} {bits:>7.1f}")

# ─── Hint impact for each best config ────────────────────────────
if best:
    print()
    print("=" * 75)
    print("Security loss from kappa = 2m(k-1) hints")
    print("=" * 75)
    for n, (lq, m, m_tot, bits) in sorted(best.items()):
        n_eff = n * k
        b_no, b_full = hint_impact(n, lq)
        loss = b_no - b_full
        print(f"  n={n}, log2(q)={lq}: "
              f"no hints={b_no:.1f} bits, "
              f"with {2*m*(k-1)} hints={b_full:.1f} bits, "
              f"loss={loss:.1f} bits")

# ─── Correctness note ─────────────────────────────────────────────
print()
print("=" * 75)
print("NOTE on Correctness (Table 4.1)")
print("=" * 75)
print("""
Correctness requires q > 4 * sigma_2 * sqrt(m)  where sigma_2 = PSampPre width.

From Table 4.1:
  sigma_2 >= BU * delta * BC * omega(log m)
  BU      >= smax(SCor) * m^2 * k
  BC      >= eta_C * sqrt(2m~) * (m - m~)

This sigma_2 >> chi_0.  The LWE security above is independent of sigma_2
(it uses chi_0 only).  A valid concrete instantiation must additionally
verify q > 4 * sigma_2 * sqrt(m) by deriving sigma_2 from the full
parameter chain in Table 4.1.

Rule of thumb from ALLW25-style schemes: log2(q) >= log2(sigma_2) + log2(sqrt(m)) + 2.
With m as above and sigma_2 ~ poly(m, k, n), typically log2(q) = 40-60 for n=256.
""")
