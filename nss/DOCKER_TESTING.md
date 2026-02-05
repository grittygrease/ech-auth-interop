# Docker-Based NSS Interop Testing

## Quick Start

Run interop tests in Docker (requires Docker installed):

```bash
cd nss
./test-interop-docker.sh
```

Or manually:

```bash
docker build -t nss-echauth-test -f nss/Dockerfile .
docker run --rm nss-echauth-test
```

## What This Tests

The Docker container:
1. Clones NSS 3.120 from Mozilla's Mercurial repository
2. Applies the ECH Auth patch (`nss_echauth.patch`)
3. Builds NSS with ECH Auth support
4. Compiles the interop test program
5. Runs tests against Go/Rust-signed test vectors:
   - `test-vectors/go_signed_rpk.ech`
   - `test-vectors/go_signed_pkix.ech`
   - `test-vectors/rust_signed_rpk.ech`
   - `test-vectors/rust_signed_pkix.ech`

## Test Coverage

### Parsing Tests
- NSS parses Go-signed RPK configs
- NSS parses Go-signed PKIX configs
- NSS parses Rust-signed RPK configs
- NSS parses Rust-signed PKIX configs
- Verifies method detection (RPK vs PKIX)
- Verifies PKIX `not_after=0` compliance

### What's Validated

**Success criteria for each test:**
- Parse completes without errors (`SECSuccess`)
- Method field correctly identifies RPK (0x00) or PKIX (0x01)
- For PKIX: `notAfter` field is 0 (per draft spec)

**This proves:**
- Wire format compatibility between implementations
- NSS correctly handles Go/Rust encoding
- PKIX compliance enforcement works

## Build Time

First build: ~5-7 minutes (clones and builds NSS from source)
Subsequent builds: ~30 seconds (Docker cache)

## Architecture

The Dockerfile uses multi-stage build:

### Stage 1: NSS Builder
```
ubuntu:22.04 + NSS build dependencies
→ Clone NSS 3.120 from hg.mozilla.org
→ Apply nss_echauth.patch
→ Build NSS (./build.sh)
→ Output: /build/nss-repo/out/Debug (libraries)
```

### Stage 2: Test Runner
```
ubuntu:22.04 + runtime libraries
→ Copy NSS libraries from stage 1
→ Copy NSS source headers for compilation
→ Compile interop_test.c against NSS
→ Run tests
```

## Prerequisites

- Docker installed
- Test vectors in `test-vectors/` directory

## Troubleshooting

### "docker: command not found"
Install Docker: https://docs.docker.com/get-docker/

### Build fails at Mercurial clone
Network issue or hg.mozilla.org down. Try again later.

### Test files not found
Ensure test vectors exist:
```bash
ls -la test-vectors/{go,rust}_signed_{rpk,pkix}.ech
```

## CI Integration

To use Docker in GitHub Actions, update `.github/workflows/ci.yml`:

```yaml
- name: Build and test with Docker
  run: |
    docker build -t nss-echauth-test -f nss/Dockerfile .
    docker run --rm nss-echauth-test
```

This replaces the current manual gcc compilation steps.

## Local Development

For iterative development without rebuilding NSS each time:

```bash
# Build once
docker build -t nss-echauth-test -f nss/Dockerfile .

# Mount test vectors for easy updates
docker run --rm -v $(pwd)/test-vectors:/test/test-vectors:ro nss-echauth-test
```

## Expected Output

```
=== NSS ECH Auth Interop Tests ===

--- Go Implementation Vectors ---
PASS: test_go_rpk_vector
PASS: test_go_pkix_vector
SKIP: test_go_pkix_invalid_not_after (vector not generated)

--- Rust Implementation Vectors ---
PASS: test_rust_rpk_vector
PASS: test_rust_pkix_vector

=== Test Results ===
Passed: 4
Failed: 0
```

Exit code 0 = all tests passed
Exit code 1 = some tests failed

## Next Steps

After successful Docker test runs:
1. Update interop matrix in README.md with ✓ for NSS verification
2. Consider adding NSS signing tests (test `SSL_SignEchConfig`)
3. Add Docker-based tests to CI workflow
