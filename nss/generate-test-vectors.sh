#!/bin/bash
# Generate ECH Auth test vectors for NSS interop testing

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VECTORS_DIR="${SCRIPT_DIR}/../test-vectors/nss"

echo "=== Generating NSS Test Vectors ==="

mkdir -p "${VECTORS_DIR}"
cd "${SCRIPT_DIR}/../go"

# Generate RPK test vector
echo ""
echo "Generating RPK test vector..."
go run cmd/ech-auth/main.go \
    -gen-vector \
    -method rpk \
    -out "${VECTORS_DIR}/rpk_vector.bin"

# Generate PKIX test vector (with not_after=0)
echo "Generating PKIX test vector..."
go run cmd/ech-auth/main.go \
    -gen-vector \
    -method pkix \
    -not-after 0 \
    -out "${VECTORS_DIR}/pkix_vector.bin"

# Generate invalid PKIX (not_after != 0) - should be rejected
echo "Generating INVALID PKIX test vector (not_after != 0)..."
go run cmd/ech-auth/main.go \
    -gen-vector \
    -method pkix \
    -not-after 12345 \
    -out "${VECTORS_DIR}/pkix_invalid_not_after.bin"

echo ""
echo "=== Test vectors generated in ${VECTORS_DIR} ==="
ls -lh "${VECTORS_DIR}"
