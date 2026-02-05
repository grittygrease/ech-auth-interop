#!/bin/bash
# Standalone NSS ECH Auth build and test script
# This script clones NSS, applies the ECH Auth patch, builds it, and runs tests

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${SCRIPT_DIR}/../nss-build-tmp"
NSS_REPO="${WORK_DIR}/nss"

echo "=== NSS ECH Auth Build and Test ==="
echo "Script dir: ${SCRIPT_DIR}"
echo "Work dir: ${WORK_DIR}"
echo ""

# Clean up any previous build
if [ -d "${WORK_DIR}" ]; then
    echo "Cleaning up previous build..."
    rm -rf "${WORK_DIR}"
fi

mkdir -p "${WORK_DIR}"
cd "${WORK_DIR}"

# Step 1: Clone NSS
echo ""
echo "=== Cloning NSS ==="
hg clone https://hg.mozilla.org/projects/nss
cd nss

# Try stable branch first, fall back to default
hg update NSS_3_97_BRANCH || hg update default

# Step 2: Apply patch
echo ""
echo "=== Applying ECH Auth patch ==="
patch -p1 < "${SCRIPT_DIR}/nss_echauth.patch"

# Step 3: Build NSS
echo ""
echo "=== Building NSS ==="
./build.sh

# Step 4: Compile test binary
echo ""
echo "=== Compiling ECH Auth tests ==="
cd dist/Debug/lib
gcc -o "${SCRIPT_DIR}/tls13echauth_test" \
    "${SCRIPT_DIR}/tls13echauth_test.c" \
    -I../include/nss \
    -I../include/nspr \
    -L. \
    -lssl3 -lnss3 -lnssutil3 -lplc4 -lplds4 -lnspr4 \
    -Wl,-rpath,\$ORIGIN \
    -Wl,-rpath,"$(pwd)" \
    -Wall -Wextra

# Step 5: Run tests
echo ""
echo "=== Running ECH Auth tests ==="
cd "${SCRIPT_DIR}"
LD_LIBRARY_PATH="${NSS_REPO}/dist/Debug/lib:${LD_LIBRARY_PATH}" \
    ./tls13echauth_test

echo ""
echo "=== Build and test complete! ==="
echo "NSS build available at: ${NSS_REPO}"
echo "Test binary: ${SCRIPT_DIR}/tls13echauth_test"
