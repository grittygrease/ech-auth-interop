# ECH Auth Interop Test Harness

This directory contains tools for testing ECH Authentication interoperability across multiple implementations.

## Components

### 1. Test Vectors (`test-vectors/interop.json`)

JSON file containing standardized test cases with:
- ECHConfig (to-be-signed portion)
- Signatures and authenticators
- Expected verification results
- Trust anchors for validation

Schema: `test-vectors/schema.json`

### 2. Test Harness (Python)

Simple test runner that works across all implementations:

```bash
# Run all tests
python3 interop/harness.py

# List available tests
python3 interop/harness.py --list

# Test specific implementation
python3 interop/harness.py --impl rust

# Run specific test
python3 interop/harness.py --test "Go RPK"

# Verbose output
python3 interop/harness.py -v
```

### 3. Vector Generator

Generate JSON test vectors from binary `.ech` files:

```bash
python3 interop/generate-vectors.py > test-vectors/interop.json
```

## Adding a New Implementation

To add your implementation to the interop test suite:

### 1. Implement Verification CLI

Your implementation should provide a command-line tool that:
- Takes a signed ECHConfig file
- Verifies the signature
- Returns exit code 0 for success, non-zero for failure

Example interface:
```bash
your-tool verify --config signed.ech --time 1234567890 --trust-anchor <spki_hash>
```

### 2. Register in Test Harness

Edit `interop/harness.py` and add to `discover_implementations()`:

```python
# Your implementation
if Path("yourimpl/Makefile").exists():
    impls.append(Implementation(
        name="YourImpl",
        verify_cmd=["./yourimpl-verify"],
        working_dir="yourimpl"
    ))
```

### 3. Generate Test Vectors

Create signed ECHConfigs and add to `test-vectors/`:
```bash
your-tool sign --key key.der --config config.ech --output yourimpl_signed_rpk.ech
```

Update `interop/generate-vectors.py`:
```python
test_files = [
    ...
    ("yourimpl_signed_rpk.ech", "YourImpl RPK signature verification", "yourimpl"),
]
```

### 4. Run Tests

```bash
python3 interop/harness.py --impl yourimpl
```

All existing implementations should be able to verify your signatures, and vice versa.

## Test Vector Format

Each test vector includes:

```json
{
  "name": "Test name",
  "description": "What this tests",
  "method": "rpk" | "pkix",
  "test_type": "valid" | "invalid_*",
  "ech_config": "hex",
  "signature": {
    "algorithm": 2055,
    "not_after": 1234567890,
    "authenticator_hex": "...",
    "signature_hex": "..."
  },
  "verification": {
    "current_time": 1234567890,
    "trust_anchors": {
      "rpk_spki_hashes": ["..."]
    }
  },
  "expected": {
    "valid": true,
    "spki_hash_hex": "...",
    "signed_ech_config_hex": "..."
  },
  "source": "go" | "rust" | "nss"
}
```

## Current Test Coverage

- ✅ RPK (Ed25519): Go ↔ Rust ↔ NSS
- ✅ PKIX (Ed25519): Go ↔ Rust ↔ NSS
- ⏳ Negative tests (invalid signatures, expired, etc.)
- ⏳ ECDSA P-256 test vectors

## CI Integration

Tests run automatically in GitHub Actions:
- Validates all implementations can verify each other's signatures
- Ensures wire format compatibility
- Catches regressions

See `.github/workflows/ci.yml` for details.
