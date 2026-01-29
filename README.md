# ECH Auth Interop

Reference implementations of [draft-sullivan-tls-signed-ech-updates](https://datatracker.ietf.org/doc/draft-sullivan-tls-signed-ech-updates/) in Rust, Go, and NSS (C).

This draft defines authenticated ECH configuration distribution, allowing TLS clients to verify that ECH retry configs received during handshake rejection come from the legitimate server operator.

## Interop Matrix

All implementations interoperate for signing and verification:

| Sign \ Verify | Rust | Go  | NSS |
|---------------|:----:|:---:|:---:|
| **Rust**      |  ✓   |  ✓  |  ✓  |
| **Go**        |  ✓   |  ✓  |  ✓  |
| **NSS**       |  ✓   |  ✓  |  ✓  |

Tested with:
- Ed25519 signatures
- ECDSA P-256 signatures
- Real TLS 1.3 ECH handshakes with rejection/retry

## Authentication Methods

### RPK (Raw Public Key)

Uses SPKI hash pinning similar to HPKP/DANE. The client pins SHA-256 hashes of trusted public keys and verifies signatures directly.

Supported algorithms:
- Ed25519 (recommended)
- ECDSA P-256

### PKIX (Certificate Chain)

Uses X.509 certificate chains with WebPKI validation. Requires certificates with the `id-pe-echConfigSigning` extension.

## Structure

```
.
├── rust/           # Rust implementation (ech-auth crate)
│   ├── src/
│   │   ├── lib.rs
│   │   ├── codec.rs      # Wire format encoding/decoding
│   │   ├── types.rs      # Auth struct and methods
│   │   ├── sign.rs       # Signing operations
│   │   ├── verify.rs     # Verification with webpki
│   │   ├── ech_config.rs # ECHConfig parsing
│   │   └── bin/          # CLI tools
│   └── Cargo.toml
├── go/             # Go implementation (echauth package)
│   ├── echauth.go        # Core types and RPK
│   ├── pkix.go           # PKIX signing
│   ├── config.go         # ECHConfig parsing and verification
│   ├── *_test.go         # Tests including E2E TLS
│   └── go.mod
└── nss/            # NSS implementation (C patch)
    ├── tls13echauth.h    # Public API
    ├── tls13echauth.c    # Implementation
    ├── echauth_client.c  # Test client
    ├── nss_echauth.patch # Integration patch
    └── README.md
```

## Usage

### Rust

```bash
cd rust
cargo build --release

# Generate a signing key
cargo run --bin ech-generate -- --algorithm ed25519 --output key.json

# Sign an ECHConfig
cargo run --bin ech-sign -- --key key.json --config echconfig.bin --output signed.bin

# Verify a signed ECHConfig
cargo run --bin ech-verify -- --config signed.bin --trust-anchor <spki-hash>
```

### Go

```go
import "github.com/grittygrease/ech-auth-interop/go"

// Create RPK auth with Ed25519
priv, _ := ed25519.GenerateKey(rand.Reader)
auth := echauth.NewRPKAuth(echauth.AlgEd25519, priv)

// Sign ECH config
now := uint64(time.Now().Unix())
signed, _ := auth.Sign(echConfigBytes, now, now+86400)

// Verify with pinned SPKI hash
anchor := &echauth.TrustAnchor{TrustedKeys: []echauth.SPKIHash{spkiHash}}
configs, err := echauth.VerifyConfigList(signedConfigList, anchor, func() uint64 {
    return uint64(time.Now().Unix())
})
```

### NSS

```c
#include "tls13echauth.h"

// Set trust anchors (SPKI hashes)
PRUint8 spkiHash[32] = { /* SHA-256 of SPKI */ };
SSL_SetEchAuthTrustAnchors(fd, &spkiHash, 1);

// ECH Auth verification happens automatically during
// retry config processing in tls13_ClientHandleEchXtn()
```

See `nss/README.md` for build instructions and patch application.

## Testing

### Rust (42 tests)

```bash
cd rust && cargo test
```

- Wire format encoding/decoding
- Ed25519 and ECDSA P-256 signing/verification
- SPKI hash computation
- Timestamp validation
- Error cases

### Go (87 tests)

```bash
cd go && go test -v
```

- All Rust test cases
- ECHConfig/ECHConfigList parsing
- Full client flow simulation
- End-to-end TLS 1.3 ECH handshakes
- ECH rejection and retry scenarios

### Cross-Implementation Interop

```bash
# Generate test vector from Rust
cd rust
cargo run --bin gen-test-vector > ../test-vectors/vector.json

# Verify in Go
cd ../go
go test -run TestInterop -v

# Verify with NSS client against Go server
cd ../nss
make test
```

## End-to-End TLS Test

The Go implementation includes full E2E tests with real TLS handshakes:

```bash
cd go
go test -run TestE2E -v
```

This tests:
1. Client connects with ECH config
2. Server rejects ECH (simulating key rotation)
3. Server sends signed retry config
4. Client verifies signature against pinned SPKI
5. Client reconnects with new config
6. ECH succeeds

## Wire Format

The `ech_auth` extension (type 0xff01, TBD) in ECHConfig:

```
struct {
    AuthMethod method;           // 1 byte: 0=none, 1=rpk, 2=pkix
    uint64 not_before;          // 8 bytes
    uint64 not_after;           // 8 bytes
    SignatureAlgorithm alg;     // 2 bytes
    opaque spki<0..2^16-1>;     // Public key (RPK) or cert chain (PKIX)
    opaque signature<0..2^16-1>;
} ECHAuthExtension;
```

## Security Considerations

- **Time validation**: All implementations enforce not_before/not_after bounds
- **Algorithm agility**: Supports multiple signature algorithms
- **Fail-closed**: Empty trust anchors reject all configs (no silent fallback)
- **Legacy mode**: Nil/null trust anchor allows unverified configs for gradual deployment
- **SPKI pinning**: SHA-256 of SubjectPublicKeyInfo, similar to HPKP

## License

MIT OR Apache-2.0
