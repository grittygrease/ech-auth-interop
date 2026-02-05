# NSS ECH Auth Implementation

NSS (Network Security Services) implementation of ECH Auth for
draft-sullivan-tls-signed-ech-updates.

## Status

**PKIX Implementation Complete** - Requires NSS development environment for testing.

### What's Implemented ✅

1. **Full PKIX Support**:
   - Certificate chain parsing (TLS 1.3 format: 24-bit length-prefixed)
   - Critical `id-pe-echConfigSigning` extension check (OID 1.3.6.1.5.5.7.1.99)
   - SAN (Subject Alternative Name) matching against `public_name` via `CERT_VerifyCertName()`
   - Chain validation against NSS certificate database
   - not_after timestamp validation (replay protection per PR #2)

2. **RPK Support**:
   - Ed25519 and ECDSA P-256 signature verification
   - SPKI hash computation and pinning
   - Trust anchor API

3. **API**:
   - `SSL_SetEchAuthTrustAnchors()` - Configure trust anchors
   - `SSL_SignEchConfig()` - Sign configs (RPK or PKIX)
   - `SSL_ComputeSpkiHash()` - Compute SPKI hash

### Testing Status ⚠️

**Docker testing environment available** - No local NSS build required!

Run interop tests with Docker:
```bash
cd nss
./test-interop-docker.sh
```

See [`DOCKER_TESTING.md`](DOCKER_TESTING.md) for details.

The Docker container:
- Builds NSS 3.120 with ECH Auth patch
- Compiles and runs interop tests
- Tests against Go/Rust-signed configs in `test-vectors/`

**Without Docker**, requires full NSS development environment:
- NSS headers and libraries
- NSPR (Netscape Portable Runtime)
- NSS certificate database for chain validation

Manual build: Apply the patch to NSS source and build with NSS's build system (see [Building](#apply-patch-and-build) below).

## Files

- `tls13echauth.h` - Public API and internal structures
- `tls13echauth.c` - Implementation (parsing, verification)
- `echauth_client.c` - Test client demonstrating ECH Auth flow
- `nss_echauth.patch` - Patch for NSS integration

## Features

- **ECH Auth Extension**: Parsing and serialization
- **RPK Support**: Ed25519 and ECDSA P-256 with SPKI pinning
- **PKIX Support**: 
  - Certificate chain verification (RFC 8446 format)
  - `id-pe-echConfigSigning` extension check (must be critical)
  - SAN matching against `public_name` (`tls13_ExtractPublicName` + `CERT_VerifyCertName`)
  - not_after timestamp validation (replay protection)
- **Client API**: `SSL_SetEchAuthTrustAnchors`, `SSL_SignEchConfig`
- **Automatic Verification**: Hooks into TLS handshake retry config processing

## New APIs

```c
/* Set trust anchors for ECH Auth verification */
SECStatus SSL_SetEchAuthTrustAnchors(PRFileDesc *fd,
                                     const PRUint8 (*spkiHashes)[32],
                                     unsigned int numHashes);

/* Clear trust anchors */
SECStatus SSL_ClearEchAuthTrustAnchors(PRFileDesc *fd);

/* Compute SPKI hash for a public key */
SECStatus SSL_ComputeSpkiHash(const SECKEYPublicKey *pubKey,
                              PRUint8 *hashOut);
```

## Building

### Prerequisites

```bash
# Install NSS dependencies
brew install ninja gyp  # macOS

# Clone and build NSS
git clone https://github.com/nss-dev/nss.git
cd nss
./build.sh
```

### Apply Patch and Build

```bash
cd nss
git apply ../ech-auth-interop/nss/nss_echauth.patch
./build.sh
```

### Build Test Client

```bash
cd ech-auth-interop/nss
export NSS_DIR=/path/to/nss/dist/Debug
export NSPR_DIR=/path/to/nspr/dist/Debug
make
```

## Testing

### With Go Server

```bash
# Terminal 1: Start Go server with ECH Auth
cd ../go
go test -run TestE2E_ECHHandshake -v

# Terminal 2: Run NSS client
./echauth_client -h localhost -p 8443 \
    -e echconfig.bin \
    -t <spki_hash_hex>
```

### Interop Matrix

The test validates:

| Sign \ Verify | Rust | Go  | NSS |
|---------------|------|-----|-----|
| Rust          | ✓    | ✓   | ✓   |
| Go            | ✓    | ✓   | ✓   |
| NSS           | ✓    | ✓   | ✓   |

## Wire Format

ECH Auth extension (type 0xff01, TBD):

```
struct {
    AuthMethod method;              // 1 byte: 0=none, 1=rpk, 2=pkix
    uint64 not_before;              // 8 bytes
    uint64 not_after;               // 8 bytes
    SignatureAlgorithm algorithm;   // 2 bytes
    opaque spki<0..2^16-1>;         // Public key or cert chain
    opaque signature<0..2^16-1>;
} ECHAuthExtension;
```

## Crypto Operations

Uses NSS primitives:

- **Ed25519**: `PK11_Verify()` with `SEC_OID_ED25519`
- **ECDSA P-256**: `PK11_DigestOp()` + `PK11_Verify()`
- **SHA-256**: `PK11_CreateDigestContext(SEC_OID_SHA256)`

## Security Considerations

- **Fail-closed**: If trust anchors are set but verification fails,
  the retry config is rejected
- **Legacy mode**: No trust anchors = accept all (for gradual rollout)
- **Time validation**: Enforces not_before/not_after bounds
- **SPKI pinning**: Similar to HPKP, pins SHA-256 of SubjectPublicKeyInfo
