#!/bin/bash
#
# ECH Auth Interop Test Matrix
#
# Tests cross-implementation signing and verification:
#   - Same-version tests (PR2↔PR2, Published↔Published)
#   - Cross-version tests (PR2↔Published - expected failures)
#   - Rust signs → Go verifies
#   - Go signs → Rust verifies
#   - Rust signs → Rust verifies
#   - Go signs → Go verifies

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
WORK_DIR="$SCRIPT_DIR/work"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Results tracking
PASS_COUNT=0
FAIL_COUNT=0
RESULTS=""

pass() {
    printf "${GREEN}PASS${NC}\n"
    RESULTS="$RESULTS$1:PASS\n"
    PASS_COUNT=$((PASS_COUNT + 1))
}

fail() {
    printf "${RED}FAIL${NC}: %s\n" "$2"
    RESULTS="$RESULTS$1:FAIL\n"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

echo "============================================"
echo "  ECH Auth Interop Test Matrix"
echo "============================================"
echo ""

# Setup
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

# Build tools
echo "Building tools..."

printf "  Rust CLI... "
cd "$ROOT_DIR/rust"
if cargo build --release --quiet 2>/dev/null; then
    printf "${GREEN}OK${NC}\n"
    RUST_BIN="$ROOT_DIR/rust/target/release"
else
    printf "${RED}FAILED${NC}\n"
    exit 1
fi

printf "  Go CLI... "
cd "$ROOT_DIR/go"
if go build -o "$WORK_DIR/ech-auth-go" ./cmd/ech-auth 2>/dev/null; then
    printf "${GREEN}OK${NC}\n"
    GO_BIN="$WORK_DIR"
else
    printf "${RED}FAILED${NC}\n"
    exit 1
fi

cd "$WORK_DIR"
echo ""

# Create test ECH config (as hex for Rust)
# fe0d = version, 0020 = length 32, then 32 zero bytes
CONFIG_HEX="fe0d00200000000000000000000000000000000000000000000000000000000000000000"
printf '%s' "$CONFIG_HEX" | xxd -r -p > config.bin
echo "Test data created:"
echo "  Config TBS: $(printf '%s' "$CONFIG_HEX" | wc -c | tr -d ' ') hex chars"

# Not-after timestamp (24 hours from now)
NOT_AFTER=$(($(date +%s) + 86400))
echo "  Not after: $NOT_AFTER"

echo ""
echo "============================================"
echo "  Test 1: Rust Sign → Rust Verify"
echo "============================================"
echo ""

printf "Running... "
TEST_NAME="rust_rust"
if (
    set -e
    # Use gen-test-vector to get known key values
    "$RUST_BIN/gen-test-vector" > vector.json 2>/dev/null
    SPKI_HASH=$(cat vector.json | python3 -c "import json,sys; print(json.load(sys.stdin)['spki_hash_hex'])")
    SIGNING_KEY=$(cat vector.json | python3 -c "import json,sys; print(json.load(sys.stdin)['signing_key_hex'])")

    # Create key file (32 bytes)
    printf '%s' "$SIGNING_KEY" | xxd -r -p > rust_key.bin

    # Sign with Rust
    printf '%s' "$CONFIG_HEX" | "$RUST_BIN/ech-sign" \
        --method rpk --algorithm ed25519 \
        --key rust_key.bin \
        --not-after "$NOT_AFTER" > rust_signed.hex 2>/dev/null

    SIGNED_HEX=$(cat rust_signed.hex)

    # Verify with Rust
    printf '%s' "$SIGNED_HEX" | "$RUST_BIN/ech-verify" \
        --config-tbs "$CONFIG_HEX" \
        --trusted-key "$SPKI_HASH" >/dev/null 2>&1
) 2>/dev/null; then
    pass "$TEST_NAME"
else
    fail "$TEST_NAME" "verification failed"
fi

echo ""
echo "============================================"
echo "  Test 2: Rust Sign → Go Verify"
echo "============================================"
echo ""

printf "Running... "
TEST_NAME="rust_go"
if (
    set -e
    # Get SPKI hash from vector
    SPKI_HASH=$(cat vector.json | python3 -c "import json,sys; print(json.load(sys.stdin)['spki_hash_hex'])")

    # Use already-signed rust_signed.hex
    SIGNED_HEX=$(cat rust_signed.hex)

    # Convert hex to binary for Go
    printf '%s' "$SIGNED_HEX" | xxd -r -p > rust_signed.bin

    # Verify with Go
    "$GO_BIN/ech-auth-go" verify \
        --config rust_signed.bin \
        --trust-anchor "$SPKI_HASH" >/dev/null 2>&1
) 2>/dev/null; then
    pass "$TEST_NAME"
else
    fail "$TEST_NAME" "verification failed"
fi

echo ""
echo "============================================"
echo "  Test 3: Go Sign → Go Verify"
echo "============================================"
echo ""

printf "Running... "
TEST_NAME="go_go"
if (
    set -e
    # Generate key with Go
    "$GO_BIN/ech-auth-go" generate \
        --algorithm ed25519 \
        --output go_key.json >/dev/null 2>&1

    SPKI_HASH=$(cat go_key.json | python3 -c "import json,sys; print(json.load(sys.stdin)['spki_hash_hex'])")

    # Sign with Go
    "$GO_BIN/ech-auth-go" sign \
        --key go_key.json \
        --config config.bin \
        --not-after "$NOT_AFTER" \
        --output go_signed.bin >/dev/null 2>&1

    # Verify with Go
    "$GO_BIN/ech-auth-go" verify \
        --config go_signed.bin \
        --trust-anchor "$SPKI_HASH" >/dev/null 2>&1
) 2>/dev/null; then
    pass "$TEST_NAME"
else
    fail "$TEST_NAME" "verification failed"
fi

echo ""
echo "============================================"
echo "  Test 4: Go Sign → Rust Verify"
echo "============================================"
echo ""

printf "Running... "
TEST_NAME="go_rust"
if (
    set -e
    # Use go_key.json and go_signed.bin from test 3
    SPKI_HASH=$(cat go_key.json | python3 -c "import json,sys; print(json.load(sys.stdin)['spki_hash_hex'])")

    # Convert Go signed output to hex for Rust
    GO_SIGNED_HEX=$(xxd -p go_signed.bin | tr -d '\n')

    # Verify with Rust
    printf '%s' "$GO_SIGNED_HEX" | "$RUST_BIN/ech-verify" \
        --config-tbs "$CONFIG_HEX" \
        --trusted-key "$SPKI_HASH" >/dev/null 2>&1
) 2>/dev/null; then
    pass "$TEST_NAME"
else
    fail "$TEST_NAME" "verification failed"
fi

echo ""
echo "============================================"
echo "  Test 5: Deterministic Vector"
echo "============================================"
echo ""

printf "Rust vector → Go verify... "
TEST_NAME="vector_rust_go"
if (
    set -e
    SPKI_HASH=$(cat vector.json | python3 -c "import json,sys; print(json.load(sys.stdin)['spki_hash_hex'])")
    ECH_AUTH_HEX=$(cat vector.json | python3 -c "import json,sys; print(json.load(sys.stdin)['ech_auth_encoded_hex'])")

    # Convert to binary for Go
    printf '%s' "$ECH_AUTH_HEX" | xxd -r -p > vector_signed.bin

    # Verify with Go
    "$GO_BIN/ech-auth-go" verify \
        --config vector_signed.bin \
        --trust-anchor "$SPKI_HASH" >/dev/null 2>&1
) 2>/dev/null; then
    pass "$TEST_NAME"
else
    fail "$TEST_NAME" "verification failed"
fi

echo ""
echo "============================================"
echo "  Results Summary"
echo "============================================"
echo ""

# Print results table
printf "%-25s | %-10s\n" "Test" "Result"
printf "%-25s-+-%-10s\n" "-------------------------" "----------"

for test in rust_rust rust_go go_go go_rust vector_rust_go; do
    result=$(printf '%b' "$RESULTS" | grep "^$test:" | cut -d: -f2)
    if [ "$result" = "PASS" ]; then
        printf "%-25s | ${GREEN}%-10s${NC}\n" "$test" "$result"
    elif [ "$result" = "FAIL" ]; then
        printf "%-25s | ${RED}%-10s${NC}\n" "$test" "$result"
    else
        printf "%-25s | ${YELLOW}%-10s${NC}\n" "$test" "SKIP"
    fi
done

echo ""

# Summary
TOTAL=$((PASS_COUNT + FAIL_COUNT))
if [ "$FAIL_COUNT" -eq 0 ]; then
    printf "${GREEN}All %d tests passed!${NC}\n" "$PASS_COUNT"
    exit 0
else
    printf "${RED}%d of %d tests failed${NC}\n" "$FAIL_COUNT" "$TOTAL"
    exit 1
fi
