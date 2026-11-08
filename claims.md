# Claim-to-evidence index

Each claim links to the runnable script that produced it and the
unedited output file (with its SHA-256 digest from
`outputs/SHA256SUMS`). "Run" means the harness run; run1 and run2
agree on every claim below (see `outputs/run-comparison.log`).

File digests (from `outputs/SHA256SUMS`):

- `outputs/run1/differential-run.log` —
  `9efded85bfd8e80a004d5042484b32bb72a038273a328ef385937c2aeb6936c7`
- `outputs/run1/results.json` —
  `6c507a89a9c9c8ddabf6e4ce7957f273aa1fe36bb17e82588d4a242628f92996`
- `outputs/run2/differential-run.log` —
  `44e67dd5e6729ba447d8b4660ed83c0e327697f1c652cc9de3c2a929397a6a96`
- `outputs/run2/results.json` —
  `68643125f11f22ac326c28e5de9eed4645020e95d6f9749a4656025139e389ab`
- `outputs/run-comparison.log` —
  `84602e88404ea57bcd01663286b233606b4ee2238bdc060f5a878d02585b73cc`

Reproduce any claim with: `./run_all.sh <new-run-name>` (builds both
implementations and re-runs the harness; see `README.md`).

## C-01 — Both implementations implement FIPS 203 implicit rejection (Algorithm 18)

**Claim.** liboqs 0.16.0 and kyber-py 1.2.0 both implement
ML-KEM.Decaps_internal (Algorithm 18): on re-encryption failure the
returned secret is `K̄ = J(z‖c)`.

**Script:** `src/run_differential.py` (function `fallback_secret`,
independent `hashlib.shake_256` recomputation);
`src/mlkem-liboqs-driver.c` (implementation A driver).

**Evidence:** `outputs/run1/results.json` — every rejected 1088-byte
case has `liboqs.ss_sha256 == kyber_py.ss_sha256 ==
expected_fallback_sha256`; `outputs/run1/differential-run.log`,
differential-cases section, verdict `PASS` for all 18 rejected cases.

## C-02 — Valid encapsulations agree across implementations in both directions

**Claim.** For valid ciphertexts, both implementations return the
encapsulation shared secret, whether the ciphertext was produced by
kyber-py or by liboqs, and whether the keypair came from kyber-py
(`key_derive`) or liboqs (random `keypair`).

**Script:** `src/run_differential.py` (valid-rounds loop, 20 rounds × 3
directions).

**Evidence:** `outputs/run1/results.json`,
`summary.valid_rounds_pass = 20 / 20`;
`outputs/run1/differential-run.log`, "valid encapsulation agreement"
section.

## C-03 — Malformed ciphertexts are handled per FIPS 203 Sec. 7.3

**Claim.** Wrong-length ciphertexts (0, 1, 512, 1087, 1089, 2048
bytes) are refused by both implementations; 1088-byte malformed
ciphertexts (bit flips, all-zero, all-0xFF, seeded random) return the
implicit-rejection fallback.

**Script:** `src/run_differential.py` (`build_cases`, malformed
category).

**Evidence:** `outputs/run1/results.json`, cases
`malformed-trunc-*`, `malformed-ext-*`, `malformed-flip-*`,
`malformed-all-*`, `malformed-random*` — all `PASS`;
`outputs/run1/differential-run.log`, malformed rows.

## C-04 — Adversarial ciphertexts return the fallback, never an error

**Claim.** Ciphertexts crafted to fail the re-encryption check (valid
ciphertext under a different keypair; u-part saturated; v-part
saturated; u-part zeroed) return `J(z‖c)` from both implementations,
never an error and never the encapsulation secret.

**Script:** `src/run_differential.py` (`build_cases`, adversarial
category).

**Evidence:** `outputs/run1/results.json`, cases
`adversarial-cross-key`, `adversarial-u-saturated`,
`adversarial-v-saturated`, `adversarial-u-zeroed` — all `PASS` with
`ss_sha256 == expected_fallback_sha256`.

## C-05 — Decapsulation is deterministic and cross-implementation consistent

**Claim.** Repeated decapsulation of the same (dk, ct) returns the
same secret in each implementation, and the two implementations agree
with each other, for both valid and malformed inputs.

**Script:** `src/run_differential.py` (determinism section, 5 repeats
× 2 inputs).

**Evidence:** `outputs/run1/results.json`,
`summary.determinism_ok = true`;
`outputs/run1/differential-run.log`, determinism section.

## C-06 — The Sec. 7.3 decapsulation-key hash check is enforced by both implementations

**Claim.** A decapsulation key whose stored `H(ek)` is corrupted is
refused by both: kyber-py raises `ValueError('hash check failed')`,
liboqs returns error status `-1` (via mlkem-native
`mlk_kem_check_sk`). Wrong-length decapsulation keys (2399, 2401
bytes) are refused by both.

**Script:** `src/run_differential.py` (input-checks section).

**Evidence:** `outputs/run1/results.json`, `input_checks` (6 entries);
`outputs/run1/differential-run.log`, input-checks section.
Source confirmation: `citations.md` §3 (mlkem-native `kem.c`).

## C-07 — Timing: no success-vs-failure latency difference above noise

**Claim.** With n=100 decapsulations per cell, the median
failure-minus-success latency delta is −0.006 µs (liboqs) and
+22 µs (kyber-py) in run1, and −0.009 µs / +44 µs in run2 — a
fraction of the observed run-to-run spread. This is a measurement
result only; it is not a proof of timing indistinguishability.

**Script:** `src/run_differential.py` (timing section, `perf_counter_ns`
for kyber-py, `CLOCK_MONOTONIC` in the driver for liboqs).

**Evidence:** `outputs/run1/results.json` and
`outputs/run2/results.json`, `timing` objects (medians, p5, p95,
means, min/max, n=100 per cell);
`outputs/run1/differential-run.log`, timing section.
Environment: AMD EPYC 9D25, Linux 7.0.0-43-generic x86_64, Python
3.12.3 — recorded in `results.json` → `env`.

## C-08 — The clean reproduction reproduces every verdict

**Claim.** A second run from a fresh copy of this repository
(`outputs/run2/`) reproduces every case verdict, cross-implementation
agreement, fallback equality, and input-check outcome of run1.
Timing values and the random liboqs keypair digests legitimately
differ (encapsulation uses fresh randomness; latency varies).

**Script:** `src/compare_runs.py`,
`outputs/run1/results.json`, `outputs/run2/results.json`.

**Evidence:** `outputs/run-comparison.log` — "REPRODUCIBILITY: all
verdicts, agreements, fallback equalities and input-check outcomes
identical between runs." The comparison script documents exactly
which fields are compared and which are excluded and why.

## C-09 — Severity-ranked findings

**Claim.** Findings F-01 (Medium) through F-05 (Low) in
`findings.md` are each derived from an observed behavior or a
verified source property listed in `citations.md`; no failure was
invented. The headline result is agreement: no cross-implementation
disagreement was found.

**Script:** `src/run_differential.py` + `src/compare_runs.py`.

**Evidence:** `findings.md` (per-finding evidence locations);
`outputs/run1/results.json` (`summary.disagreements = []`,
`summary.failures = []`).
