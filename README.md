# ECH Auth Interop

[![CI](https://github.com/grittygrease/ech-auth-interop/workflows/CI/badge.svg)](https://github.com/grittygrease/ech-auth-interop/actions)

Reference implementations of [draft-sullivan-tls-signed-ech-updates](https://datatracker.ietf.org/doc/draft-sullivan-tls-signed-ech-updates/) in Rust, Go, and NSS (C).

This draft defines authenticated ECH configuration distribution, allowing TLS clients to verify that ECH retry configs received during handshake rejection come from the legitimate server operator.

## Quick Start

**New to the project?** Start here:

1. **Read the overview**: [What is ECH Auth?](#authentication-methods)
2. **Choose your language**:
   - **Rust**: See [`rust/README.md`](rust/README.md) for installation and examples
   - **Go**: Check [Usage](#go) below for quick start
   - **NSS (C)**: See [`nss/README.md`](nss/README.md) for patch application
3. **Integration guide**: See [`INTEGRATION.md`](INTEGRATION.md) for TLS stack integration patterns

### For Implementers

If you're implementing ECH Auth in your TLS stack:
1. Read the [wire format](#wire-format) section
2. Review the [Rust examples](rust/examples/) for reference implementations
3. Check the [interop matrix](#interop-matrix) for compatibility
4. Run the [cross-implementation tests](#cross-implementation-interop)

## Interop Matrix

All implementations interoperate for signing and verification:

### RPK (Raw Public Key)

| Sign \ Verify | Rust | Go  | NSS |
|---------------|:----:|:---:|:---:|
| **Rust**      |  ✓   |  ✓  |  ✓  |
| **Go**        |  ✓   |  ✓  |  ✓  |

NSS is client-focused and doesn't implement signing (servers use Go/Rust).

Algorithms tested:
- Ed25519 (recommended)
- ECDSA P-256 (secp256r1)

### PKIX (Certificate-Based)

| Sign \ Verify | Rust | Go  | NSS |
|---------------|:----:|:---:|:---:|
| **Rust**      |  ✓   |  ✓  |  ✓  |
| **Go**        |  ✓   |  ✓  |  ✓  |

NSS is client-focused and doesn't implement signing (servers use Go/Rust).

**NSS Implementation Status**: 
- **Client Verification**: ✅ Fully working - NSS clients can verify configs signed by Go/Rust servers ([Docker test evidence](https://github.com/grittygrease/ech-auth-interop/actions))
- **Server Signing**: Not implemented (NSS is client-focused; servers typically use Go/Rust)
- **Features**: Complete PKIX and RPK support including:
  - Certificate chain parsing and validation
  - Critical `id-pe-echConfigSigning` extension check
  - SAN matching against public_name
  - PKIX `not_after=0` compliance enforcement

**Testing NSS Interop:**
```bash
# Requires Docker
cd nss
./test-interop-docker.sh
```

Docker tests validate NSS parsing of:
- `test-vectors/go_signed_rpk.ech` (Go RPK → NSS)
- `test-vectors/go_signed_pkix.ech` (Go PKIX → NSS)
- `test-vectors/rust_signed_rpk.ech` (Rust RPK → NSS)
- `test-vectors/rust_signed_pkix.ech` (Rust PKIX → NSS)

See [`nss/DOCKER_TESTING.md`](nss/DOCKER_TESTING.md) for Docker setup and [`nss/README.md`](nss/README.md) for implementation details.

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
│   │   ├── lib.rs        # Main library with comprehensive docs
│   │   ├── trust.rs      # Trust model (DNS, caching, downgrade protection)
│   │   ├── verify.rs     # Signature verification (RPK & PKIX)
│   │   ├── sign.rs       # Signing operations
│   │   ├── types.rs      # Wire format types
│   │   ├── ech_config.rs # ECHConfig parsing
│   │   ├── codec.rs      # Encoding/decoding utilities
│   │   ├── error.rs      # Error types
│   │   └── bin/          # CLI tools (ech-sign, ech-verify, gen-test-vector)
│   ├── examples/         # Working examples (5 files)
│   ├── README.md         # Rust-specific documentation
│   └── Cargo.toml
├── go/             # Go implementation (echauth package)
│   ├── echauth.go        # Core types and verification
│   ├── trust.go          # Trust model implementation
│   ├── pkix.go           # PKIX certificate validation
│   ├── config.go         # ECHConfig parsing
│   ├── encoding.go       # Wire format utilities
│   ├── *_test.go         # Comprehensive test suite
│   └── go.mod
├── nss/            # NSS implementation (C patch)
│   ├── tls13echauth.h    # Public API
│   ├── tls13echauth.c    # Implementation (RPK & PKIX)
│   ├── echauth_client.c  # Test client
│   ├── nss_echauth.patch # Integration patch
│   └── README.md
└── INTEGRATION.md  # Guide for integrating with TLS stacks
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

## Quality Checks

To ensure code quality, run the following before submitting changes:

### Rust
```bash
cd rust
cargo clippy
cargo fmt --check
```

### Go
```bash
cd go
go vet ./...
go fmt ./...
```

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

Implements the split-extension format from draft-sullivan-tls-signed-ech-updates.

### Method Encoding

| Method | Value |
|--------|-------|
| rpk    | 0     |
| pkix   | 1     |

### ech_authinfo Extension

Policy extension for DNS HTTPS records:

```
struct {
    uint8 method;                          // 1 byte: 0=rpk, 1=pkix
    SPKIHash trusted_keys<0..2^16-1>;     // N * 32-byte SHA-256 hashes
} ECHAuthInfo;
```

### ech_auth Extension

Signature extension for TLS retry configs:

```
struct {
    uint8 method;                          // 1 byte: 0=rpk, 1=pkix
    uint64 not_after;                      // 8 bytes: Unix timestamp
    opaque authenticator<1..2^16-1>;       // SPKI (RPK) or cert chain (PKIX)
    SignatureScheme algorithm;             // 2 bytes
    opaque signature<1..2^16-1>;
} ECHAuth;
```

**Key features:**
- Policy (trusted_keys) separated from signature for DNS efficiency
- `not_after` required for both RPK and PKIX (replay limiting)
- PKIX authenticator contains X.509 certificate chain in TLS 1.3 format

## Security Considerations

- **Time validation**: All implementations enforce `not_after` expiration
- **Algorithm agility**: Supports multiple signature algorithms
- **Fail-closed**: Empty trust anchors reject all configs (no silent fallback)
- **Legacy mode**: Nil/null trust anchor allows unverified configs for gradual deployment
- **SPKI pinning**: SHA-256 of SubjectPublicKeyInfo, similar to HPKP

## License

MIT OR Apache-2.0
