# NSS ECH Auth Implementation

NSS (Network Security Services) implementation of ECH Auth for
draft-sullivan-tls-signed-ech-updates.

## Status

**Work in Progress** - This is a reference implementation showing how
ECH Auth would integrate with NSS's existing ECH support.

## Files

- `tls13echauth.h` - Public API and internal structures
- `tls13echauth.c` - Implementation (parsing, verification)
- `echauth_client.c` - Test client demonstrating ECH Auth flow
- `nss_echauth.patch` - Patch for NSS integration

## Integration Points

The ECH Auth verification hooks into NSS at these points:

1. **ECHConfig parsing** (`tls13_DecodeEchConfigs` in `tls13ech.c`)
   - Parse `ech_auth` extension from each config's extensions
   - Store in extended `sslEchConfig` structure

2. **Retry config handling** (`tls13_ClientHandleEchXtn` in `tls13exthandle.c`)
   - After receiving retry configs, verify ECH Auth signatures
   - Reject configs that fail verification if trust anchors are set

3. **Socket structure** (`sslSocket` in `sslimpl.h`)
   - Add `echAuthTrustAnchor` field for pinned SPKI hashes

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
