# RFC Compliance Matrix

Compliance analysis for draft-sullivan-tls-signed-ech-updates-00.

## Legend
- ✓ Implemented and tested
- ⚠ Partial/untested
- ✗ Not implemented
- N/A Not applicable

## Section 3.1: RPK (Raw Public Key)

| Requirement | Rust | Go | NSS |
|-------------|:----:|:--:|:---:|
| MUST compute sha256(spki) | ✓ | ✓ | ✓ |
| MUST verify membership in trusted_keys | ✓ | ✓ | ✓ |
| MUST verify not_after > current_time | ✓ | ✓ | ✓ |
| MUST verify signature over TBS | ✓ | ✓ | ⚠ |
| MUST clear RPK state on expiration | N/A | N/A | N/A |

**Notes:**
- Go: `VerifyRPK()` checks `sig.NotAfter` strictly greater than `now`
- Rust: `verify_rpk()` checks `current_time >= not_after` returns error
- Tests: `TestVerifyRPK_ExactlyAtExpiration` verifies edge case

## Section 3.2: PKIX Certificate-Based

| Requirement | Rust | Go | NSS |
|-------------|:----:|:--:|:---:|
| MUST include critical id-pe-echConfigSigning | ✓ | ✓ | ✓ |
| MUST validate certificate chain | ✓ | ✓ | ✓ |
| MUST confirm SAN covers public_name | ⚠ | ✓ | ✓ |
| MUST confirm critical extension presence | ✓ | ✓ | ✓ |
| MUST verify signature with leaf key | ✓ | ✓ | ✓ |
| MUST NOT accept cert for TLS server auth | ✓ | ✓ | ✓ |
| MUST verify not_after > current_time | ✓ | ✓ | ✓ |

**Notes:**
- PR #2: not_after is required for both RPK and PKIX (provides replay protection)
- Rust: Uses webpki for chain validation, SAN check only validates extension presence
- Go: Full PKIX implementation with complete SAN matching
- NSS: Full PKIX implementation with `tls13_ExtractPublicName()` and `CERT_VerifyCertName()`

## Section 5.1: ECH Authentication Extension

| Requirement | Rust | Go | NSS |
|-------------|:----:|:--:|:---:|
| MUST place ech_auth last in extensions | ✓ | ✓ | ✗ |
| MUST reject if ech_auth not last | ✓ | ✓ | ✗ |
| MUST have ≥1 hash if method=rpk | ✓ | ✓ | ⚠ |
| MUST have zero-length trusted_keys otherwise | ✓ | ✓ | ⚠ |
| MUST verify before installing ECHConfig | ✓ | ✓ | ⚠ |

**Notes:**
- Rust: Extension ordering validated in `validate_extension_ordering()` with tests
- Go: Extension ordering validated in `parseECHConfig()` as of this PR
- NSS: Extension ordering not implemented yet

## Section 5.1.1: Signature Computation

| Requirement | Rust | Go | NSS |
|-------------|:----:|:--:|:---:|
| MUST use sha256(4) for hash algorithm | ✓ | ✓ | ✓ |

## Section 5.2.3: Client Behavior

| Requirement | Rust | Go | NSS |
|-------------|:----:|:--:|:---:|
| MUST terminate and retry on ECH rejection success | N/A | ✓ | ⚠ |
| MUST NOT use retry_configs on validation failure | ✓ | ✓ | ⚠ |

**Notes:**
- Go E2E tests verify full rejection/retry flow
- Rust is library-only (no TLS stack)

## Section 7.3.1: Signature Verification

| Requirement | Rust | Go | NSS |
|-------------|:----:|:--:|:---:|
| MUST correctly implement signature verification | ✓ | ✓ | ⚠ |
| SHOULD use strong signature schemes | ✓ | ✓ | ✓ |
| SHOULD NOT use RSA PKCS#1 v1.5 | ✓ | ✓ | ✓ |
| MUST verify temporal constraints | ✓ | ✓ | ✓ |

**Supported algorithms:**
- Ed25519 (ech_auth_alg_ed25519 = 0x0807)
- ECDSA P-256 (ech_auth_alg_ecdsa_p256_sha256 = 0x0403)

## Section 9.2: X.509 Extension OID

| Requirement | Rust | Go | NSS |
|-------------|:----:|:--:|:---:|
| MUST mark id-pe-echConfigSigning critical | ✓ | ✓ | N/A |

**Notes:**
- Go: `CreateECHSigningCert()` adds critical extension
- Rust: Certificate creation includes critical extension
- Tests: `TestVerifyPKIX_NonCriticalECHExtension` verifies rejection

## Summary

### Critical Gaps (MUST violations)

1. **Extension ordering in NSS**
   - NSS C code doesn't validate ech_auth is last
   - Should be added to NSS patch

### Partial Implementations (⚠️)

1. **Rust SAN matching**: Checks extension presence but doesn't parse contents
2. **NSS testing**: Not fully integrated into CI (requires NSS build environment)

### Test Coverage

| Area | Rust | Go |
|------|------|-----|
| Valid signature verification | ✓ | ✓ |
| Expired signature rejection | ✓ | ✓ |
| Wrong key rejection | ✓ | ✓ |
| Corrupted signature rejection | ✓ | ✓ |
| Wrong TBS rejection | ✓ | ✓ |
| SPKI hash mismatch rejection | ✓ | ✓ |
| Empty trusted_keys rejection | ✓ | ✓ |
| PKIX critical extension check | ✓ | ✓ |
| PKIX expired cert rejection | ✓ | ✓ |
| PKIX untrusted root rejection | ✓ | ✓ |
| Extension ordering enforcement | ✓ | ✓ |
| E2E TLS handshake | - | ✓ |
| E2E ECH rejection/retry | - | ✓ |

**Test counts:**
- Go: 117 tests (4 new extension ordering tests)
- Rust: 54 tests

## Recommendations

1. **NSS extension ordering**: Add validation in C code that ech_auth must be last
2. **Improve Rust SAN matching**: Parse SAN contents and match against public_name
3. **NSS CI integration**: Add Docker-based NSS tests to GitHub Actions
4. **Interop harness**: Create CLI-based test matrix runner
