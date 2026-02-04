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
| MUST include critical id-pe-echConfigSigning | ✓ | ✓ | ✗ |
| MUST validate certificate chain | ✓ | ✓ | ⚠ |
| MUST confirm SAN covers public_name | ⚠ | ✓ | ✗ |
| MUST confirm critical extension presence | ✓ | ✓ | ✗ |
| MUST verify signature with leaf key | ✓ | ✓ | ⚠ |
| MUST NOT accept cert for TLS server auth | ✓ | ✓ | ✗ |
| MUST set not_after=0 for PKIX | ✓ | ✓ | ✗ |

**Notes:**
- Go: `VerifyPKIX()` checks `auth.Method == MethodPKIX` and `auth.NotAfter != 0`
- Rust: Uses webpki for chain validation
- NSS: PKIX not implemented yet

## Section 5.1: ECH Authentication Extension

| Requirement | Rust | Go | NSS |
|-------------|:----:|:--:|:---:|
| MUST place ech_auth last in extensions | ✗ | ✗ | ✗ |
| MUST reject if ech_auth not last | ✗ | ✗ | ✗ |
| MUST have ≥1 hash if method=rpk | ✓ | ✓ | ⚠ |
| MUST have zero-length trusted_keys otherwise | ✓ | ✓ | ⚠ |
| MUST verify before installing ECHConfig | ✓ | ✓ | ⚠ |

**KNOWN GAPS:**
- **Extension ordering**: None of the implementations enforce ech_auth being last
- This is a MUST in section 5.1

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

1. **Extension ordering (Section 5.1)**
   - All implementations: Do not enforce ech_auth being last
   - Fix required in `Encode()` and `Decode()` functions

2. **NSS PKIX support**
   - Not implemented (RPK only)

### Partial Implementations

1. **NSS**: All verification is scaffolding (not compiled/tested against real NSS)
2. **SAN matching**: Rust doesn't enforce SAN covers public_name

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
| E2E TLS handshake | - | ✓ |
| E2E ECH rejection/retry | - | ✓ |

## Recommendations

1. **Fix extension ordering**: Add checks in decode to verify ech_auth is last
2. **Complete NSS**: Apply patch, build, run against Go server
3. **Add SAN check to Rust**: Verify public_name matches certificate SAN
4. **Interop harness**: Create CLI-based test matrix runner
