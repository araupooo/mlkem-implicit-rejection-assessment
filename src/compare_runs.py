#!/usr/bin/env python3
"""Compare two differential runs (results.json) on everything that must be
reproducible, ignoring values that legitimately vary run to run:
  * timing measurements (medians/percentiles),
  * timestamps,
  * digests of the randomly generated liboqs keypair (keygen is random),
  * the liboqs driver READY line is identical by construction.
Everything else -- every case verdict, every cross-implementation agreement,
every fallback-secret equality, every input-check outcome, valid-round and
determinism results -- must match exactly.
Usage: compare_runs.py <results1.json> <results2.json>
"""
import json
import sys

r1 = json.load(open(sys.argv[1]))
r2 = json.load(open(sys.argv[2]))

diffs = []


def cmp(label, a, b):
    if a != b:
        diffs.append(f"{label}: run1={a!r} run2={b!r}")


# deterministic keypair must be identical (same public seed)
cmp("keypair.ek_sha256", r1["keypair"]["ek_sha256"], r2["keypair"]["ek_sha256"])
cmp("keypair.dk_sha256", r1["keypair"]["dk_sha256"], r2["keypair"]["dk_sha256"])
cmp("keypair.dk_hash_check", r1["keypair"]["dk_hash_check"], r2["keypair"]["dk_hash_check"])
cmp("keypair.z_sha256", r1["keypair"]["z_sha256"], r2["keypair"]["z_sha256"])

# every case: verdict and agreement must match. Digest VALUES are not
# compared across runs: encapsulation uses fresh randomness each run, so
# the valid ciphertext (and every ciphertext derived from it) legitimately
# differs. What must reproduce is the RELATIONSHIP inside each run:
# both implementations return the same secret, and that secret equals the
# independently recomputed fallback J(z||c) where applicable.
c1 = {c["case"]: c for c in r1["cases"]}
c2 = {c["case"]: c for c in r2["cases"]}
cmp("case id sets", sorted(c1), sorted(c2))
for cid in sorted(c1):
    a, b = c1[cid], c2[cid]
    cmp(f"{cid}.verdict", a["verdict"], b["verdict"])
    cmp(f"{cid}.cross_impl_agree", a["cross_impl_agree"], b["cross_impl_agree"])
    for run, row in (("run1", a), ("run2", b)):
        la, lb = row["liboqs"]["ss_sha256"], row["kyber_py"]["ss_sha256"]
        fb = row.get("expected_fallback_sha256")
        if la is not None and lb is not None and la != lb:
            diffs.append(f"{cid}.{run}: liboqs ss != kyber-py ss")
        if fb is not None and la is not None and la != fb:
            diffs.append(f"{cid}.{run}: liboqs ss != independently computed fallback")

# input checks: outcomes and error classes must match
for x, y in zip(r1["input_checks"], r2["input_checks"]):
    cmp(f"input_check {x['check']}.outcome", x["outcome"], y["outcome"])
    # error text must match up to the random-free prefix (same for both runs)
    cmp(f"input_check {x['check']}.error", x.get("error"), y.get("error"))

# summary counters
for k in ["cases_total", "cases_pass", "cases_fail", "valid_rounds_pass",
          "valid_rounds_total", "determinism_ok"]:
    cmp(f"summary.{k}", r1["summary"][k], r2["summary"][k])
cmp("summary.disagreements", r1["summary"]["disagreements"], r2["summary"]["disagreements"])
cmp("summary.failures", r1["summary"]["failures"], r2["summary"]["failures"])

# timing: report only (not compared for equality -- measurements vary)
print("timing (run1 -> run2, medians in ms):")
for key in ["liboqs-success", "liboqs-failure", "kyber-py-success", "kyber-py-failure"]:
    print(f"  {key}: {r1['timing'][key]['median_ms']} -> {r2['timing'][key]['median_ms']}")
print(f"  liboqs delta: {r1['timing']['liboqs-delta-median-ms']} -> {r2['timing']['liboqs-delta-median-ms']}")
print(f"  kyber-py delta: {r1['timing']['kyber-py-delta-median-ms']} -> {r2['timing']['kyber-py-delta-median-ms']}")

if diffs:
    print(f"\nREPRODUCIBILITY: {len(diffs)} DIFFERENCE(S)")
    for d in diffs:
        print("  -", d)
    sys.exit(1)
print("\nREPRODUCIBILITY: all verdicts, agreements, fallback equalities and "
      "input-check outcomes identical between runs.")
sys.exit(0)
