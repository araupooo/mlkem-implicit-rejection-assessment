#!/usr/bin/env bash
# Reproduce the ML-KEM implicit-rejection differential assessment end to end.
#
#   ./run_all.sh [run-name]        # default run-name: run1
#
# What it does:
#   1. Builds liboqs 0.16.0 from the bundled tarball (ML-KEM only, Release),
#      verifying the tarball SHA-256 first.
#   2. Compiles the liboqs stdin driver (src/mlkem-liboqs-driver.c).
#   3. Creates a Python venv and installs kyber-py 1.2.0 from the bundled
#      wheel (no network needed).
#   4. Runs the differential harness (src/run_differential.py) into
#      outputs/<run-name>/, producing differential-run.log (unedited) and
#      results.json.
#   5. Regenerates SHA256SUMS over outputs/ (run from the pack root).
#
# Requirements: gcc, cmake, make, python3 (>= 3.10), OpenSSL dev headers
# (libssl-dev) for -lcrypto, ~500 MB free disk for the liboqs build.
# No network access is needed: all sources are bundled under src/.
set -euo pipefail
cd "$(dirname "$0")"

RUN="${1:-run1}"
OUT="outputs/$RUN"
LIBOQS_TARBALL="src/liboqs-0.16.0.tar.gz"
LIBOQS_SHA256="162d5b510518ee5f285f82fa1f16402a885176e818bf1b1a4c3c91c9a2f01eae"
KYBER_WHEEL="src/kyber_py-1.2.0-py3-none-any.whl"

echo "=== ML-KEM implicit-rejection assessment: $RUN ==="
echo "date (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- 1. liboqs ---
echo "$LIBOQS_SHA256  $LIBOQS_TARBALL" | sha256sum -c -
if [ ! -d src/liboqs-0.16.0 ]; then
  echo "extracting liboqs 0.16.0 ..."
  tar xzf "$LIBOQS_TARBALL" -C src
fi
if [ ! -f src/liboqs-build/lib/liboqs.a ]; then
  echo "configuring liboqs (ML-KEM only) ..."
  mkdir -p src/liboqs-build
  (cd src/liboqs-build && cmake ../liboqs-0.16.0 -DCMAKE_BUILD_TYPE=Release \
    -DOQS_BUILD_ONLY_LIB=ON -DOQS_DIST_BUILD=OFF \
    -DOQS_ENABLE_KEM_BIKE=OFF -DOQS_ENABLE_KEM_FRODOKEM=OFF \
    -DOQS_ENABLE_KEM_NTRUPRIME=OFF -DOQS_ENABLE_KEM_NTRU=OFF \
    -DOQS_ENABLE_KEM_CLASSIC_MCELIECE=OFF -DOQS_ENABLE_KEM_HQC=OFF \
    -DOQS_ENABLE_KEM_KYBER=OFF -DOQS_ENABLE_SIG_ML_DSA=OFF \
    -DOQS_ENABLE_SIG_FALCON=OFF -DOQS_ENABLE_SIG_MAYO=OFF \
    -DOQS_ENABLE_SIG_CROSS=OFF -DOQS_ENABLE_SIG_UOV=OFF \
    -DOQS_ENABLE_SIG_SNOVA=OFF -DOQS_ENABLE_SIG_MQOM=OFF \
    -DOQS_ENABLE_SIG_SLH_DSA=OFF > ../../outputs/build-liboqs-cmake.log 2>&1)
  echo "building liboqs ..."
  (cd src/liboqs-build && make -j"$(nproc)" > ../../outputs/build-liboqs-make.log 2>&1)
fi
ls -la src/liboqs-build/lib/liboqs.a

# --- 2. driver ---
echo "compiling liboqs driver ..."
gcc -O2 -Wall -I src/liboqs-build/include -o src/mlkem-liboqs-driver \
  src/mlkem-liboqs-driver.c src/liboqs-build/lib/liboqs.a -lcrypto

# --- 3. kyber-py venv ---
if [ ! -x venv/bin/python ]; then
  echo "creating venv and installing kyber-py 1.2.0 from bundled wheel ..."
  python3 -m venv venv
  venv/bin/pip install --quiet --no-index --find-links src kyber-py==1.2.0
fi
venv/bin/python -c "import kyber_py; from importlib.metadata import version; print('kyber-py', version('kyber-py'))"

# --- 4. differential run ---
mkdir -p "$OUT"
echo "running differential harness -> $OUT ..."
venv/bin/python src/run_differential.py \
  --driver src/mlkem-liboqs-driver --outdir "$OUT" \
  --timing-n 100 --valid-n 20

# --- 5. checksums over outputs ---
(cd outputs && find . -type f ! -name SHA256SUMS -exec sha256sum {} + | sort -k2 > SHA256SUMS)
echo "=== done: $RUN ==="
echo "log:     $OUT/differential-run.log"
echo "results: $OUT/results.json"
echo "checksums: outputs/SHA256SUMS"
