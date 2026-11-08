# Findings — ML-KEM Implicit-Rejection Assessment

Severity-ranked findings from the differential runs
(`outputs/run1/`, `outputs/run2/`; both runs 19/19 cases PASS, 20/20
valid rounds, zero cross-implementation disagreements). Every finding
is an actually observed behavior or a verified property, with the
evidence location given. No failures were invented: where the
implementations agree, that is stated as the finding.

## F-01 — Medium: liboqs `OQS_KEM_decaps` performs no ciphertext/key length check; callers must validate

**Observed.** `OQS_KEM_decaps` takes three bare pointers
(`shared_secret`, `ciphertext`, `secret_key`) and no lengths
(`src/kem/kem.h` in liboqs 0.16.0: "Caller is responsible for
allocating sufficient memory"). The FIPS 203 Sec. 7.3 ciphertext and
decapsulation-key type checks therefore cannot be performed by the
library function itself. In this assessment the length checks are
enforced by the driver (`src/mlkem-liboqs-driver.c`) before any call:
a 1087-byte ciphertext is refused with
`ciphertext type check failed: expected 1088 bytes, got 1087`, and a
2399/2401-byte decapsulation key with the analogous message
(`outputs/run1/differential-run.log`, input-checks section). A caller
that passes a short buffer directly to `OQS_KEM_decaps` gets no
refusal from the library — the fixed-size code would read past the
supplied buffer. (Calling the library with a short buffer was not
tested, because it would be an out-of-bounds read; the claim is about
the API shape, verified in the header, not about an observed crash.)

**Why it matters.** FIPS 203 Sec. 7.3 requires the ciphertext check
"with every execution of ML-KEM.Decaps". An integrator who treats
`OQS_KEM_decaps` as a complete implementation of Algorithm 21 and
feeds it unvalidated network input is missing a required check and
risks a memory-safety fault. Mitigation: validate lengths against the
`length_*` members before calling, as the driver does.

**Severity: Medium.** The failure mode requires a caller mistake, the
library documents the caller-responsibility contract, and the
decapsulation-key hash check *is* performed inside the library (see
F-05) — but the missing ciphertext length check is a real, required
check that the API cannot express.

## F-02 — Low: error-signalling conventions differ at the API boundary

**Observed.** For the same invalid inputs, kyber-py raises a Python
`ValueError` (`Validation of decapsulation key or ciphertext failed:
e = ValueError('ciphertext type check failed. Expected 1088 bytes and
obtained 1087')`), while the liboqs path returns an error status
(`decaps returned -1` for a corrupted stored `H(ek)`) or a driver-level
refusal string for wrong lengths. Both refuse; the *mechanism* differs
(exception vs. status code), and the wrong-length refusal for liboqs
comes from the driver, not the library (see F-01).

**Why it matters.** Integrators bridging the two APIs (or comparing
their behaviour) must handle two different failure channels; a caller
that only checks one channel can mistake a refusal for a success.
Low severity: both implementations refuse, and the difference is
visible in the logs rather than silent.

## F-03 — Low (verified behaviour, no disagreement): implicit rejection is byte-identical across implementations

**Observed.** For all 14 malformed 1088-byte ciphertexts and all 4
adversarial ciphertexts, liboqs and kyber-py return the same 32-byte
secret, and that secret equals `J(z || c)` recomputed independently
in the harness with `hashlib.shake_256` (`outputs/run1/results.json`,
`expected_fallback_sha256` matches both `liboqs.ss_sha256` and
`kyber_py.ss_sha256` in every rejected case). Valid encapsulations
agree as well (20/20 rounds in both directions, including a
liboqs-generated keypair decapsulated by kyber-py). Repeated
decapsulation of the same input is deterministic in both
implementations (5/5 repeats, valid and malformed inputs).

**Why it is recorded.** The brief asks for severity-ranked findings
from observed differences; the headline observation is that there are
no differences in the implicit-rejection path. This is a positive,
evidence-backed result, ranked Low because it requires no action.

## F-04 — Low: no measurable success-vs-failure latency difference above noise — with explicit limits

**Observed** (n=100 decapsulations per cell, AMD EPYC 9D25,
Linux 7.0.0-43-generic x86_64):

| Implementation | Success median | Failure median | Median delta | Success p95 | Failure p95 |
| --- | --- | --- | --- | --- | --- |
| liboqs (run1) | 0.024808 ms | 0.024802 ms | −0.000006 ms | 0.033586 ms | 0.033399 ms |
| liboqs (run2) | 0.025037 ms | 0.025028 ms | −0.000009 ms | 0.025180 ms | 0.026358 ms |
| kyber-py (run1) | 7.557161 ms | 7.579589 ms | +0.022428 ms | 9.475211 ms | 7.976014 ms |
| kyber-py (run2) | 7.433044 ms | 7.477486 ms | +0.044442 ms | 8.766325 ms | 7.911753 ms |

The deltas are a fraction of the run-to-run spread (kyber-py p95
varies by ~1.5 ms between runs; the success p95 exceeds the failure
p95 in run1). Nothing here is distinguishable from noise.

<a id="timing-limits"></a>
**Limits — read before citing this.** These are wall-clock
measurements of whole decapsulation calls on one shared virtual
machine, n=100 per cell. They do **not** prove timing
indistinguishability and must not be cited as such. Not measured:
per-operation or cache-timing behaviour, power/EM leakage, behaviour
under contention, other CPUs, or larger samples. A constant-time
claim would require a dedicated side-channel evaluation, which this
assessment is not.

## F-05 — Low (verified behaviour): both implementations perform the Sec. 7.3 decapsulation-key hash check

**Observed.** A decapsulation key whose stored `H(ek)` byte is flipped
(hash check fails) is refused by both: kyber-py raises
`ValueError('hash check failed')`; liboqs returns error status `-1`.
Source confirmation: kyber-py `_decaps_internal` compares
`self._H(ek_pke) != h` and raises; mlkem-native `mlk_kem_dec` calls
`mlk_kem_check_sk`, which recomputes `H(ek)` and returns
`MLK_ERR_FAIL` on mismatch (`src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/kem.c`,
lines 76–114 and 396). Note FIPS 203 Sec. 7.3 allows the decapsulation-key
check to be assured "through other means" rather than on every
execution; both implementations chose to check on every decapsulation.

## What was not found

- No case where the two implementations disagreed on a returned secret.
- No case where a rejected ciphertext returned anything other than
  `J(z || c)`.
- No case where decapsulation signalled failure by returning an error
  instead of a 32-byte secret for a correctly-sized input (both
  implementations always return 32 bytes for 1088-byte ciphertexts,
  as Algorithm 18 requires).
- No timing delta above noise (F-04).

## Summary table

| ID | Severity | One line |
| --- | --- | --- |
| F-01 | Medium | liboqs C API has no length parameters; the Sec. 7.3 type checks are the caller's job |
| F-02 | Low | Failure signalling differs: kyber-py raises, liboqs returns a status / driver refusal |
| F-03 | Low | Implicit rejection byte-identical across implementations; equals independently computed `J(z\|\|c)` |
| F-04 | Low | No success-vs-failure latency delta above noise; not a proof of indistinguishability |
| F-05 | Low | Both implementations perform the Sec. 7.3 decapsulation-key hash check on every decapsulation |
