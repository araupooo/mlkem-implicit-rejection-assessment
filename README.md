# ML-KEM Implicit-Rejection Assessment

Differential assessment of FIPS 203 implicit rejection in two independent
ML-KEM-768 implementations: **liboqs 0.16.0** (C, via mlkem-native) and
**kyber-py 1.2.0** (pure Python). Both implement ML-KEM.Decaps (FIPS 203
Algorithm 21 / Algorithm 18): decapsulation never signals failure; when the
re-encryption check fails, it returns the implicit-rejection fallback
`K' = J(z || c)` (SHAKE256, 32 bytes), where `z` is the 32-byte rejection
value stored in the decapsulation key.

## Result in one paragraph

19 differential cases (1 valid, 14 malformed, 4 adversarial) plus 20
valid-encapsulation rounds in both directions: **all pass, zero
disagreements**. For every 1088-byte rejected ciphertext, both
implementations return byte-identical secrets, and each equals the
fallback `J(z || c)` recomputed independently with `hashlib.shake_256`.
Both implementations refuse a decapsulation key whose stored `H(ek)`
does not match the embedded encapsulation key (FIPS 203 Sec. 7.3 hash
check), and both refuse wrong-length ciphertexts and keys. Timing:
no measurable success-vs-failure latency difference above noise in
either implementation (liboqs median delta −0.006 µs; kyber-py median
delta +22 µs against a ~7.5 ms median and a ~2 ms p95 spread, n=100 per
cell). These measurements do **not** prove indistinguishability — see
[findings.md](findings.md#timing-limits) for the limits.

## Contents

| Path | What it is |
| --- | --- |
| `run_all.sh` | Reproduce everything: build, run, checksums |
| `src/mlkem-liboqs-driver.c` | stdin driver for liboqs ML-KEM-768 (implementation A) |
| `src/run_differential.py` | Differential harness (categories, fallback check, timing) |
| `src/compare_runs.py` | run1-vs-run2 reproducibility comparison |
| `src/liboqs-0.16.0.tar.gz` | liboqs source (SHA-256 below) |
| `src/kyber_py-1.2.0-py3-none-any.whl` | kyber-py wheel (SHA-256 below) |
| `src/FIPS.203.pdf` | FIPS 203 (August 2024), the specification under test |
| `fixtures/test-vectors.json` | Deterministic test keypair + valid/malformed vectors |
| `outputs/run1/`, `outputs/run2/` | Unedited run logs + machine-readable results |
| `outputs/run-comparison.log` | run1-vs-run2 reproducibility comparison |
| `outputs/build-liboqs-*.log` | liboqs configure/build logs |
| `outputs/SHA256SUMS` | Checksums over all files under `outputs/` |
| `findings.md` | Severity-ranked findings |
| `citations.md` | Primary sources with URLs |
| `claims.md` | Claim-to-evidence index |
| `evidence.json` | Machine-readable summary of results |
| `docs/index.html` | Rendered findings page (self-contained) |

## Reproduce

```sh
./run_all.sh run1
```

No network access is needed: all sources are bundled under `src/`.
Requirements: `gcc`, `cmake`, `make`, `python3` (>= 3.10), OpenSSL
development headers (`libssl-dev`, for `-lcrypto`), ~500 MB free disk
for the liboqs build. The script verifies the liboqs tarball SHA-256,
builds liboqs (ML-KEM only, Release), compiles the driver, installs
kyber-py from the bundled wheel into a local venv, runs the harness
into `outputs/<run-name>/`, and regenerates `outputs/SHA256SUMS`.

A clean reproduction was run from a fresh copy of this repository
(`outputs/run2/`); `outputs/run-comparison.log` shows that every case
verdict, cross-implementation agreement, fallback equality, and
input-check outcome is identical between the two runs. Timing values
and the random liboqs keypair digests legitimately differ between runs;
see the comparison log for what is compared and why. Note: the
unedited `outputs/build-liboqs-cmake.log` contains one absolute local
build path (a cmake-generated line); it is kept unedited as required
for raw logs.

## Implementations

| | A: liboqs | B: kyber-py |
| --- | --- | --- |
| Version | 0.16.0 (tarball SHA-256 `162d5b51…f01eae`) | 1.2.0 (wheel SHA-256 `517f4c8f…da6aa`) |
| Language | C (ML-KEM backend: mlkem-native ref + x86_64) | pure Python |
| FIPS 203 basis | ML-KEM-768, `OQS_KEM_decaps` | `ML_KEM_768.decaps` (Algorithm 21) |
| Implicit rejection | mlkem-native `mlk_kem_dec`: `J(z\|\|c)` on re-encryption mismatch, constant-time select | `ML_KEM._decaps_internal`: `K_bar = self._J(z + c)`, select on `c == c'` |
| Sec. 7.3 hash check | performed inside decaps (`mlk_kem_check_sk`, returns error on mismatch) | performed before decaps, raises `ValueError` |
| Length type checks | **not** performed by the C API (no length parameters; caller must validate) | performed, raises `ValueError` |

The two codebases are genuinely independent: liboqs's ML-KEM descends
from mlkem-native (PQ Code Package), while kyber-py is a separate
pure-Python implementation. Key formats are the standard FIPS 203
layouts, so the same decapsulation key and ciphertext can be fed to
both implementations and the outputs compared byte-for-byte.

## Test design

Parameter set: **ML-KEM-768** (ek 1184 B, dk 2400 B, ct 1088 B, ss 32 B).
Deterministic keypair: `kyber_py.ML_KEM_768.key_derive(d || z)` with
`d, z` = SHA-256 of public labels (see `fixtures/test-vectors.json`).
The same keypair is used by both implementations; a second, random
liboqs-generated keypair is cross-checked in the other direction.

Categories (19 differential cases per run):

- **valid** (1): encapsulation under the test keypair; both
  implementations must return the encapsulation shared secret.
- **malformed** (14): truncated ct (1087, 512, 1, 0 bytes), extended ct
  (1089, 2048 bytes), single-bit flips (bytes 0, 543, 1024, 1087),
  all-zero ct, all-0xFF ct, two seeded-random ct. Wrong-length inputs
  must be refused by both; 1088-byte inputs must return the fallback.
- **adversarial** (4): a valid ciphertext under a *different* keypair
  (re-encryption check must fail), u-part saturated to 0xFF, v-part
  saturated to 0xFF, u-part zeroed. All must return the fallback.

For every 1088-byte rejected ciphertext the harness independently
recomputes the expected fallback `J(z || c)` with `hashlib.shake_256`
and requires both implementations to equal it. Additional checks:
20 valid-encapsulation rounds (kyber-py encap, liboqs encap, and
liboqs-keypair directions), 5× repeated decapsulation determinism,
6 input-check cases (corrupted stored `H(ek)`, truncated/extended dk),
and timing (n=100 decapsulations per implementation per outcome).

Logs contain SHA-256 digests of shared secrets and ciphertexts only —
never raw shared secrets. Test keypairs are generated from a public
seed for this assessment; they are test vectors, not real keys.

## Alternatives considered and not used

- **pq-crystals/kyber reference implementation**: checked first; it is
  the round-3 Kyber reference (pre-FIPS 203), no longer actively
  maintained, and its README points to mlkem-native for FIPS 203
  ML-KEM. Not used as an implementation.
- **mlkem-native directly**: not used as the second implementation
  because liboqs 0.16.0 already uses mlkem-native as its ML-KEM
  backend — the two would not be independent.
- **Go stdlib `crypto/mlkem`**: a driver existed from earlier work, but
  no Go toolchain is installed on this machine, so it could not be
  built or executed here. Not used.

## Timing limits

Wall-clock decapsulation latency only, single machine
(AMD EPYC 9D25, Linux 7.0.0-43-generic x86_64), n=100 per cell.
Medians, p5/p95, and sample counts are reported in
`outputs/run1/results.json` and `findings.md`. These numbers describe
observed latency on this machine; they are **not** a side-channel
evaluation and do **not** prove timing indistinguishability. See
[findings.md](findings.md#timing-limits).
