#!/bin/bash
#
# Run NSS ECH Auth interop tests in Docker
#
# This script builds NSS with the ECH Auth patch and runs interop tests
# against Go/Rust-signed test vectors.

set -e

cd "$(dirname "$0")/.."

echo "============================================"
echo "  NSS ECH Auth Docker Interop Testing"
echo "============================================"
echo ""

echo "Building Docker image (this may take ~5 minutes)..."
docker build -t nss-echauth-test -f nss/Dockerfile .

echo ""
echo "Running interop tests..."
docker run --rm nss-echauth-test

echo ""
echo "============================================"
echo "  Docker tests completed!"
echo "============================================"
