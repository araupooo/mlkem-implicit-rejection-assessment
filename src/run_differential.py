#!/usr/bin/env python3
"""Differential test harness: liboqs ML-KEM-768 (C, implementation A) vs
kyber-py ML-KEM-768 (pure Python, implementation B).

Both implement FIPS 203 ML-KEM.Decaps (Algorithm 21 / Algorithm 18):
on a ciphertext that fails the re-encryption check, decapsulation returns
the implicit-rejection fallback K_bar = J(z || c) (SHAKE256, 32 bytes),
where z is the 32-byte rejection value stored in the decapsulation key at
dk[768k+64 : 768k+96] (FIPS 203 Sec. 6.3, Algorithm 18 steps 4, 7, 9-10).
Decapsulation never signals failure; it always returns 32 bytes.

What this harness checks, per case:
  * cross-implementation agreement: for the same dk and ct, both
    implementations must return the same shared secret (byte-for-byte).
  * fallback correctness: for every rejected ciphertext, the returned
    secret must equal J(z || c) computed independently here with
    hashlib.shake_256 -- an independent check of Algorithm 18 step 7.
  * determinism: repeated decapsulation of the same (dk, ct) returns the
    same secret in each implementation.
  * input checks (FIPS 203 Sec. 7.3): wrong-length ct / dk, and a dk whose
    stored H(ek) does not match the embedded ek.

Logs contain SHA-256 digests of shared secrets and ciphertexts only --
never raw shared secrets. Test keypairs are generated deterministically
from a fixed public test seed (see TEST_SEED) so the run is reproducible;
they are test vectors, not real keys.

Usage:
  python3 run_differential.py --driver <path-to-mlkem-liboqs-driver> \
      --outdir <output directory> [--timing-n 100] [--valid-n 20]
"""
import argparse
import hashlib
import json
import os
import platform
import random
import subprocess
import sys
import time

# Fixed public test seed: SHA-256 of the label. Deterministic across runs.
TEST_SEED = hashlib.sha256(b"mlkem-implicit-rejection-assessment/test-seed-v1").digest()
# key_derive seed is d || z (64 bytes): d = first 32 bytes of a second hash.
KEY_SEED = hashlib.sha256(b"mlkem-implicit-rejection-assessment/key-seed-v1").digest() + \
    hashlib.sha256(b"mlkem-implicit-rejection-assessment/reject-seed-v1").digest()

PARAM = "ML-KEM-768"
K = 3
EK_LEN = 1184
DK_LEN = 2400
CT_LEN = 1088
SS_LEN = 32

# kyber-py is imported lazily so --help works without the venv.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def shake256_32(data: bytes) -> bytes:
    return hashlib.shake_256(data).digest(32)


def fallback_secret(dk: bytes, ct: bytes) -> bytes:
    """Independent recomputation of the Algorithm 18 fallback K_bar = J(z||c)."""
    z = dk[768 * K + 64: 768 * K + 96]
    return shake256_32(z + ct)


def dk_hash_check(dk: bytes) -> bool:
    """FIPS 203 Sec. 7.3 step 3: H(dk[384k:768k+32]) == dk[768k+32:768k+64]."""
    ek = dk[384 * K: 768 * K + 32]
    h = dk[768 * K + 32: 768 * K + 64]
    return hashlib.sha3_256(ek).digest() == h


def env_info():
    cpu = "unknown"
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    cpu = line.split(":", 1)[1].strip()
                    break
    except OSError:
        pass
    return {
        "date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cpu": cpu,
        "liboqs": None,  # filled in by main
        "kyber_py": None,  # filled in by main
    }


class LibOQS:
    """Implementation A: liboqs 0.16.0 (C) via the stdin driver."""

    def __init__(self, driver_path):
        self.proc = subprocess.Popen(
            [driver_path], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            text=True, bufsize=1)
        line = self.proc.stdout.readline().strip()
        if not line.startswith("READY"):
            raise RuntimeError(f"liboqs driver did not start: {line!r}")
        self.ready = line

    def cmd(self, text):
        self.proc.stdin.write(text + "\n")
        self.proc.stdin.flush()
        return self.proc.stdout.readline().strip()

    def keygen(self):
        out = self.cmd("keygen")
        parts = out.split()
        assert parts[0] == "PK" and parts[2] == "SK", out
        return bytes.fromhex(parts[1]), bytes.fromhex(parts[3])

    def encap(self, ek):
        out = self.cmd(f"encap {ek.hex()}")
        parts = out.split()
        assert parts[0] == "CT" and parts[2] == "SS", out
        return bytes.fromhex(parts[1]), bytes.fromhex(parts[3])

    def decap(self, dk, ct):
        """Returns (ss_bytes, dt_ns) or raises ValueError on ERR."""
        out = self.cmd(f"decap {dk.hex()} {ct.hex()}")
        parts = out.split()
        if parts[0] == "ERR":
            raise ValueError(" ".join(parts[1:]))
        assert parts[0] == "SS" and parts[2] == "DT", out
        return bytes.fromhex(parts[1]), int(parts[3])

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


class KyberPy:
    """Implementation B: kyber-py (pure Python FIPS 203 ML-KEM)."""

    def __init__(self):
        from kyber_py.ml_kem import ML_KEM_768
        from importlib.metadata import version as pkg_version
        self.kem = ML_KEM_768
        self.version = pkg_version("kyber-py")

    def key_derive(self, seed):
        return self.kem.key_derive(seed)

    def keygen(self):
        return self.kem.keygen()

    def encap(self, ek):
        # kyber-py encaps() returns (K, c); normalize to (ct, ss) like liboqs.
        K, c = self.kem.encaps(ek)
        return c, K

    def decap(self, dk, ct):
        t0 = time.perf_counter_ns()
        ss = self.kem.decaps(dk, ct)
        t1 = time.perf_counter_ns()
        return ss, t1 - t0


def build_cases(ek, dk, ct_valid, ss_valid, rng):
    """Return list of (case_id, category, description, ct_bytes, expect)."""
    cases = []
    cases.append(("valid-001", "valid", "valid encapsulation from kyber-py", ct_valid, "success"))
    # --- malformed ciphertexts ---
    malformed = []
    malformed.append(("trunc-1087", "truncated to 1087 bytes", ct_valid[:1087]))
    malformed.append(("trunc-512", "truncated to 512 bytes", ct_valid[:512]))
    malformed.append(("trunc-1", "truncated to 1 byte", ct_valid[:1]))
    malformed.append(("trunc-0", "empty ciphertext (0 bytes)", b""))
    malformed.append(("ext-1089", "extended by 1 byte", ct_valid + b"\x00"))
    malformed.append(("ext-2048", "extended to 2048 bytes", ct_valid + bytes(960)))
    malformed.append(("flip-first", "bit flip at byte 0", _flip(ct_valid, 0)))
    malformed.append(("flip-mid", "bit flip at byte 543", _flip(ct_valid, 543)))
    malformed.append(("flip-last", "bit flip at byte 1087", _flip(ct_valid, 1087)))
    malformed.append(("flip-vpart", "bit flip at byte 1024 (v part)", _flip(ct_valid, 1024)))
    malformed.append(("all-zero", "all-zero ciphertext", bytes(CT_LEN)))
    malformed.append(("all-ff", "all-0xFF ciphertext", bytes([0xFF]) * CT_LEN))
    malformed.append(("random", "seeded random bytes", bytes(rng.randrange(256) for _ in range(CT_LEN))))
    malformed.append(("random2", "seeded random bytes (2nd draw)", bytes(rng.randrange(256) for _ in range(CT_LEN))))
    for cid, desc, ct in malformed:
        cases.append((f"malformed-{cid}", "malformed", desc, ct, "fallback"))
    # --- adversarial ciphertexts ---
    # (a) a valid ciphertext for a DIFFERENT keypair: re-encryption check
    #     must fail under this dk (message mismatch), so fallback applies.
    cases.append(("adversarial-cross-key", "adversarial",
                  "valid ciphertext under a different encapsulation key",
                  None, "fallback"))  # ct filled in by caller
    # (b) u-part saturated: every compressed coefficient at maximum value.
    #     Decompression yields out-of-range-ish values; re-encryption fails.
    ct_u_ff = bytearray(ct_valid)
    for i in range(0, 960):
        ct_u_ff[i] = 0xFF
    cases.append(("adversarial-u-saturated", "adversarial",
                  "u part (first 960 bytes) set to 0xFF", bytes(ct_u_ff), "fallback"))
    # (c) v-part saturated.
    ct_v_ff = bytearray(ct_valid)
    for i in range(960, CT_LEN):
        ct_v_ff[i] = 0xFF
    cases.append(("adversarial-v-saturated", "adversarial",
                  "v part (last 128 bytes) set to 0xFF", bytes(ct_v_ff), "fallback"))
    # (d) ciphertext with the compressed u coefficients zeroed but v kept:
    #     decrypts to a different message, re-encryption fails.
    ct_u_zero = bytearray(ct_valid)
    for i in range(0, 960):
        ct_u_zero[i] = 0x00
    cases.append(("adversarial-u-zeroed", "adversarial",
                  "u part (first 960 bytes) set to 0x00", bytes(ct_u_zero), "fallback"))
    return cases


def _flip(ct, pos):
    b = bytearray(ct)
    b[pos] ^= 0x01
    return bytes(b)


def pct(data, p):
    s = sorted(data)
    i = (len(s) - 1) * p / 100.0
    lo, hi = int(i), min(int(i) + 1, len(s) - 1)
    frac = i - lo
    return s[lo] * (1 - frac) + s[hi] * frac


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--driver", required=True)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--timing-n", type=int, default=100)
    ap.add_argument("--valid-n", type=int, default=20)
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    log_path = os.path.join(args.outdir, "differential-run.log")
    results_path = os.path.join(args.outdir, "results.json")
    logf = open(log_path, "w", encoding="utf-8")

    def log(msg):
        print(msg)
        logf.write(msg + "\n")
        logf.flush()

    env = env_info()
    liboqs = LibOQS(args.driver)
    kypy = KyberPy()
    env["liboqs"] = liboqs.ready
    env["kyber_py"] = kypy.version
    log("=== ML-KEM implicit-rejection differential run ===")
    log(f"date_utc: {env['date_utc']}")
    log(f"platform: {env['platform']}  python: {env['python']}")
    log(f"cpu: {env['cpu']}")
    log(f"liboqs driver: {liboqs.ready}")
    log(f"kyber-py version: {kypy.version}")
    log(f"test seed (sha256 label): {TEST_SEED.hex()}")
    log(f"timing_n={args.timing_n} valid_n={args.valid_n}")

    results = {"env": env, "cases": [], "input_checks": [], "timing": {},
               "summary": {}}
    disagreements = []
    failures = []

    # ---- deterministic keypair (kyber-py key_derive, FIPS 203 format) ----
    ek, dk = kypy.key_derive(KEY_SEED)
    assert len(ek) == EK_LEN and len(dk) == DK_LEN
    log(f"\n-- deterministic keypair (key_derive, seed = d||z, 64 bytes) --")
    log(f"ek sha256: {sha256(ek)}")
    log(f"dk sha256: {sha256(dk)}")
    log(f"dk hash check (FIPS 203 Sec. 7.3 step 3): {dk_hash_check(dk)}")
    z = dk[768 * K + 64: 768 * K + 96]
    log(f"rejection key z sha256: {sha256(z)}")
    results["keypair"] = {"ek_sha256": sha256(ek), "dk_sha256": sha256(dk),
                          "z_sha256": sha256(z),
                          "dk_hash_check": dk_hash_check(dk)}

    # ---- cross-direction keypair check: liboqs keygen -> kyber-py decap ----
    ek_b, dk_b = liboqs.keygen()
    log(f"\n-- liboqs-generated keypair (random) --")
    log(f"ek sha256: {sha256(ek_b)}  dk sha256: {sha256(dk_b)}")
    log(f"dk hash check: {dk_hash_check(dk_b)}")

    # ---- valid encapsulations ----
    rng = random.Random(20261108)
    ct_valid, ss_valid = kypy.encap(ek)
    log(f"\n-- valid encapsulation (kyber-py encap) --")
    log(f"ct sha256: {sha256(ct_valid)}  ss sha256: {sha256(ss_valid)}")

    # adversarial cross-key ciphertext: encap under a different ek
    ek_other, _dk_other = kypy.key_derive(
        hashlib.sha256(b"mlkem-implicit-rejection-assessment/other-key").digest()
        + hashlib.sha256(b"mlkem-implicit-rejection-assessment/other-z").digest())
    ct_cross, _ss_cross = kypy.encap(ek_other)

    cases = build_cases(ek, dk, ct_valid, ss_valid, rng)
    # fill in the cross-key ciphertext placeholder
    cases = [(cid, cat, desc, ct_cross if cid == "adversarial-cross-key" else ct,
              exp) for (cid, cat, desc, ct, exp) in cases]

    log(f"\n-- differential cases: {len(cases)} --")
    for cid, category, desc, ct, expect in cases:
        row = {"case": cid, "category": category, "description": desc,
               "ct_len": len(ct), "ct_sha256": sha256(ct), "expected": expect}
        # Implementation B (kyber-py) -- only if length/type checks pass
        try:
            ss_b, dt_b = kypy.decap(dk, ct)
            row["kyber_py"] = {"ss_sha256": sha256(ss_b), "dt_ns": dt_b,
                               "error": None}
        except Exception as e:
            row["kyber_py"] = {"ss_sha256": None, "dt_ns": None,
                               "error": f"{type(e).__name__}: {e}"}
        # Implementation A (liboqs)
        try:
            ss_a, dt_a = liboqs.decap(dk, ct)
            row["liboqs"] = {"ss_sha256": sha256(ss_a), "dt_ns": dt_a,
                             "error": None}
        except Exception as e:
            row["liboqs"] = {"ss_sha256": None, "dt_ns": None,
                             "error": f"{type(e).__name__}: {e}"}
        # Verdicts
        a, b = row["liboqs"], row["kyber_py"]
        agree = (a["ss_sha256"] is not None and a["ss_sha256"] == b["ss_sha256"])
        row["cross_impl_agree"] = agree
        if expect == "success":
            ok = agree and a["ss_sha256"] == sha256(ss_valid)
            row["verdict"] = "PASS" if ok else "FAIL"
        elif expect == "fallback":
            fb = sha256(fallback_secret(dk, ct)) if len(ct) == CT_LEN else None
            row["expected_fallback_sha256"] = fb
            if fb is None:
                # wrong-length ct: both impls must refuse (no secret produced)
                ok = a["ss_sha256"] is None and b["ss_sha256"] is None
                row["verdict"] = "PASS" if ok else "FAIL"
            else:
                ok = agree and a["ss_sha256"] == fb
                row["verdict"] = "PASS" if ok else "FAIL"
        else:
            row["verdict"] = "?"
        if row["verdict"] != "PASS":
            failures.append(cid)
        if not agree and not (a["ss_sha256"] is None and b["ss_sha256"] is None):
            disagreements.append(cid)
        results["cases"].append(row)
        log(f"{cid:28s} {category:12s} len={len(ct):5d} "
            f"agree={agree!s:5s} verdict={row['verdict']} "
            f"liboqs={a['ss_sha256'] and a['ss_sha256'][:12] or a['error']} "
            f"kyberpy={b['ss_sha256'] and b['ss_sha256'][:12] or b['error']}")

    # ---- valid-encap agreement across both directions, valid_n rounds ----
    log(f"\n-- valid encapsulation agreement, {args.valid_n} rounds --")
    valid_pass = 0
    for i in range(args.valid_n):
        # direction 1: kyber-py encap, both decap
        ct1, ss1 = kypy.encap(ek)
        ss_a, _ = liboqs.decap(dk, ct1)
        ss_b, _ = kypy.decap(dk, ct1)
        ok1 = (ss_a == ss_b == ss1)
        # direction 2: liboqs encap, both decap
        ct2, ss2 = liboqs.encap(ek)
        ss_a2, _ = liboqs.decap(dk, ct2)
        ss_b2, _ = kypy.decap(dk, ct2)
        ok2 = (ss_a2 == ss_b2 == ss2)
        # direction 3: liboqs keypair, kyber-py encap/decap vs liboqs decap
        ct3, ss3 = kypy.encap(ek_b)
        ss_a3, _ = liboqs.decap(dk_b, ct3)
        ss_b3, _ = kypy.decap(dk_b, ct3)
        ok3 = (ss_a3 == ss_b3 == ss3)
        if ok1 and ok2 and ok3:
            valid_pass += 1
        else:
            failures.append(f"valid-round-{i}")
            log(f"round {i}: FAIL ok1={ok1} ok2={ok2} ok3={ok3}")
    log(f"valid rounds passed: {valid_pass}/{args.valid_n}")
    results["summary"]["valid_rounds_pass"] = valid_pass
    results["summary"]["valid_rounds_total"] = args.valid_n

    # ---- determinism: same (dk, ct) decapped 5x per implementation ----
    log("\n-- determinism: 5 repeated decapsulations of the same inputs --")
    det_ok = True
    for label, ct in [("valid", ct_valid),
                      ("malformed-flip", _flip(ct_valid, 100))]:
        ss_a_list = [liboqs.decap(dk, ct)[0] for _ in range(5)]
        ss_b_list = [kypy.decap(dk, ct)[0] for _ in range(5)]
        ok = len(set(ss_a_list)) == 1 and len(set(ss_b_list)) == 1 and ss_a_list[0] == ss_b_list[0]
        det_ok &= ok
        log(f"{label}: liboqs deterministic={len(set(ss_a_list)) == 1} "
            f"kyber-py deterministic={len(set(ss_b_list)) == 1} cross-agree={ss_a_list[0] == ss_b_list[0]}")
    results["summary"]["determinism_ok"] = det_ok
    if not det_ok:
        failures.append("determinism")

    # ---- FIPS 203 Sec. 7.3 input checks ----
    log("\n-- input checks (FIPS 203 Sec. 7.3) --")
    checks = []
    # 1. corrupted stored H(ek) in dk
    dk_bad_hash = bytearray(dk)
    dk_bad_hash[768 * K + 32] ^= 0x01
    dk_bad_hash = bytes(dk_bad_hash)
    log(f"dk with corrupted stored H(ek): hash check passes={dk_hash_check(dk_bad_hash)}")
    try:
        ss_b, _ = kypy.decap(dk_bad_hash, ct_valid)
        checks.append({"check": "dk-hash-check/kyber-py", "outcome": "returned ss",
                       "ss_sha256": sha256(ss_b)})
        log("  kyber-py: returned a shared secret (no refusal)")
    except Exception as e:
        checks.append({"check": "dk-hash-check/kyber-py", "outcome": "refused",
                       "error": f"{type(e).__name__}: {e}"})
        log(f"  kyber-py: refused: {e}")
    try:
        ss_a, _ = liboqs.decap(dk_bad_hash, ct_valid)
        checks.append({"check": "dk-hash-check/liboqs", "outcome": "returned ss",
                       "ss_sha256": sha256(ss_a),
                       "matches_valid_ss": ss_a == ss_valid})
        log(f"  liboqs: returned a shared secret; equals valid ss: {ss_a == ss_valid}")
    except Exception as e:
        checks.append({"check": "dk-hash-check/liboqs", "outcome": "refused",
                       "error": f"{type(e).__name__}: {e}"})
        log(f"  liboqs: refused: {e}")
    # 2. wrong-length dk for both
    for label, bad_dk in [("dk-truncated-2399", dk[:2399]),
                          ("dk-extended-2401", dk + b"\x00")]:
        try:
            kypy.decap(bad_dk, ct_valid)
            checks.append({"check": f"{label}/kyber-py", "outcome": "returned ss"})
            log(f"  kyber-py {label}: returned a shared secret")
        except Exception as e:
            checks.append({"check": f"{label}/kyber-py", "outcome": "refused",
                           "error": f"{type(e).__name__}: {e}"})
            log(f"  kyber-py {label}: refused: {e}")
        try:
            liboqs.decap(bad_dk, ct_valid)
            checks.append({"check": f"{label}/liboqs", "outcome": "returned ss"})
            log(f"  liboqs {label}: returned a shared secret")
        except Exception as e:
            checks.append({"check": f"{label}/liboqs", "outcome": "refused",
                           "error": f"{type(e).__name__}: {e}"})
            log(f"  liboqs {label}: refused: {e}")
    results["input_checks"] = checks

    # ---- timing: success vs failure decapsulation latency ----
    log(f"\n-- timing: decapsulation latency, n={args.timing_n} per cell --")
    ct_fail = _flip(ct_valid, 100)
    timing = {}
    for impl_name, fn in [
            ("liboqs", lambda c: liboqs.decap(dk, c)[1]),
            ("kyber-py", lambda c: kypy.decap(dk, c)[1])]:
        for label, ct in [("success", ct_valid), ("failure", ct_fail)]:
            samples = [fn(ct) for _ in range(args.timing_n)]
            samples_ms = [s / 1e6 for s in samples]
            stats = {
                "n": len(samples),
                "median_ms": round(pct(samples_ms, 50), 6),
                "p5_ms": round(pct(samples_ms, 5), 6),
                "p95_ms": round(pct(samples_ms, 95), 6),
                "mean_ms": round(sum(samples_ms) / len(samples_ms), 6),
                "min_ms": round(min(samples_ms), 6),
                "max_ms": round(max(samples_ms), 6),
            }
            timing[f"{impl_name}-{label}"] = stats
            log(f"  {impl_name:9s} {label:7s} n={stats['n']} median={stats['median_ms']}ms "
                f"p5={stats['p5_ms']} p95={stats['p95_ms']} mean={stats['mean_ms']}")
    for impl_name in ["liboqs", "kyber-py"]:
        s = timing[f"{impl_name}-success"]
        f = timing[f"{impl_name}-failure"]
        delta = f["median_ms"] - s["median_ms"]
        timing[f"{impl_name}-delta-median-ms"] = round(delta, 6)
        log(f"  {impl_name}: failure-success median delta = {delta:+.6f} ms "
            f"(success p95={s['p95_ms']}ms, failure p95={f['p95_ms']}ms)")
    results["timing"] = timing

    # ---- summary ----
    n_cases = len(results["cases"])
    n_pass = sum(1 for c in results["cases"] if c["verdict"] == "PASS")
    results["summary"].update({
        "cases_total": n_cases,
        "cases_pass": n_pass,
        "cases_fail": n_cases - n_pass,
        "disagreements": disagreements,
        "failures": failures,
    })
    log(f"\n=== SUMMARY ===")
    log(f"cases: {n_pass}/{n_cases} PASS; disagreements: {disagreements or 'none'}")
    log(f"valid rounds: {valid_pass}/{args.valid_n}; determinism ok: {det_ok}")
    log(f"overall: {'PASS' if not failures else 'FAIL: ' + ', '.join(failures)}")

    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    log(f"\nresults json: {results_path}")
    logf.close()
    liboqs.close()
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
