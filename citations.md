# Citations — primary sources

Every specification-derived or measured claim in this assessment traces
to one of these sources. A copy of FIPS 203 is bundled as
`src/FIPS.203.pdf` (SHA-256
`fe1f12f32a7e44ec9fdebbf400cda843a40b506dee676725234dc6f7923b6cac`).

## 1. FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard

- **Source:** National Institute of Standards and Technology (NIST),
  FIPS 203, August 2024.
- **URL:** https://csrc.nist.gov/pubs/fips/203/final
- **PDF (bundled):** https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
- **Used for:**
  - Algorithm 18 (ML-KEM.Decaps_internal), Sec. 6.3: implicit
    rejection — `z ← dk[768k+64 : 768k+96]`, `K̄ ← J(z‖c)`, and
    `K′ ← K̄` when `c ≠ c′` (steps 4, 7, 9–10). Quoted in
    `src/run_differential.py` and verified against both implementations.
  - Section 7.3 (ML-KEM.Decaps, Algorithm 21): input checks —
    ciphertext type check, decapsulation-key type check, and the hash
    check `H(dk[384k : 768k+32]) = dk[768k+32 : 768k+64]`; the
    statement that the decapsulation-key check "need not be performed
    by the decapsulating party, nor with every execution", while
    "ciphertext checking shall be performed with every execution".
  - Table 2 / Table 3 (Sec. 8): ML-KEM-768 parameters
    (k=3, η1=2, η2=2, du=10, dv=4) and sizes (ek 1184 B, dk 2400 B,
    ct 1088 B, ss 32 B).
  - Section 6.1: the decapsulation key layout
    `dk ← (dkPKE ‖ ek ‖ H(ek) ‖ z)` and the role of `z` as the
    implicit-rejection value.

## 2. liboqs 0.16.0

- **Source:** Open Quantum Safe, liboqs 0.16.0 release.
- **URL:** https://github.com/open-quantum-safe/liboqs/releases/tag/0.16.0
- **Tarball (bundled):** `src/liboqs-0.16.0.tar.gz`, SHA-256
  `162d5b510518ee5f285f82fa1f16402a885176e818bf1b1a4c3c91c9a2f01eae`
- **Used for:** implementation A. ML-KEM-768 via `OQS_KEM_decaps`
  (`src/kem/ml_kem/kem_ml_kem_768.c`), whose backend is mlkem-native
  (`src/kem/ml_kem/mlkem-native_ml-kem-768_ref/`). The API contract
  for finding F-01 is in `src/kem/kem.h`: `decaps` takes bare pointers
  with no lengths ("Caller is responsible for allocating sufficient
  memory").

## 3. mlkem-native (liboqs's ML-KEM backend)

- **Source:** PQ Code Package, mlkem-native (part of the
  Post-Quantum Cryptography Alliance).
- **URL:** https://github.com/pq-code-package/mlkem-native
- **Used for (as vendored inside liboqs 0.16.0):**
  - `mlkem/src/kem.c`, `mlk_kem_dec`: computes `J(z‖c)` on
    re-encryption mismatch and selects it with a constant-time
    conditional move (`mlk_ct_cmov_zero`).
  - `mlkem/src/kem.c`, `mlk_kem_check_sk` (lines 76–114): the
    Sec. 7.3 hash check, called from `mlk_kem_dec` (line 396),
    returning `MLK_ERR_FAIL` on mismatch — the source basis for
    finding F-05.

## 4. kyber-py 1.2.0

- **Source:** kyber-py (pure-Python FIPS 203 ML-KEM implementation).
- **URL:** https://pypi.org/project/kyber-py/1.2.0/
- **Wheel (bundled):** `src/kyber_py-1.2.0-py3-none-any.whl`, SHA-256
  `517f4c8f5009f5b4dfb8f4bfd0f6d631bf56e0cad3f709282e6450e5d8eda6aa`
- **Used for:** implementation B (`kyber_py.ml_kem.ML_KEM_768`).
  `_decaps_internal` follows Algorithm 18 (`K_bar = self._J(z + c)`,
  `select_bytes(K_bar, K_prime, c == c_prime)`) and performs the
  Sec. 7.3 length and hash checks, raising `ValueError` on failure.

## 5. pq-crystals/kyber — checked and NOT used

- **Source:** pq-crystals/kyber, commit
  `3edd5af5991927164edd4aacebfcbee00b8064e7` (2026-08-02).
- **URL:** https://github.com/pq-crystals/kyber
- **Why cited:** it was evaluated as a candidate second
  implementation and rejected: it is the round-3 Kyber reference
  (pre-FIPS 203), no longer actively maintained, and its README
  directs FIPS 203 ML-KEM users to mlkem-native. Its
  `ref/kem.c` also implements an implicit-rejection step, but for
  round-3 Kyber, not FIPS 203 ML-KEM, so it was not used.

## 6. liboqs documentation (API contract)

- **Source:** liboqs `CONFIGURE.md` / `src/kem/kem.h` in the 0.16.0
  tarball.
- **Used for:** the `OQS_KEM` API contract underlying finding F-01
  (caller-owned buffers, no length parameters on `decaps`).
