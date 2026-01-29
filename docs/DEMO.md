# ECH Auth Demo

Walkthrough of ECH authentication for signed retry configs per
[draft-sullivan-tls-signed-ech-updates](https://datatracker.ietf.org/doc/draft-sullivan-tls-signed-ech-updates/).

## Quick Start

```bash
./interop/run_matrix.sh
```

Expected output:
```
============================================
  ECH Auth Interop Test Matrix
============================================

Test                      | Result
--------------------------+-----------
rust_rust                 | PASS
rust_go                   | PASS
go_go                     | PASS
go_rust                   | PASS
vector_rust_go            | PASS

All 5 tests passed!
```

## Step-by-Step Walkthrough

### 1. Generate Test Vector

```bash
cd rust && cargo run --release --bin gen-test-vector
```

Output:
```json
{
  "algorithm": 2055,
  "ech_auth_encoded_hex": "01002006e3fd8f...375d009",
  "ech_config_tbs_hex": "746573742045434820636f6e66696720666f7220696e7465726f70",
  "name": "interop_ed25519_rpk",
  "not_after": 1893456000,
  "signing_key_hex": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  "spki_hash_hex": "06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9"
}
```

### 2. Wire Format Breakdown

The `ech_auth` extension encoding (157 bytes total):

```
Offset  Hex                                                               Field
------  ----------------------------------------------------------------  ------------------
0       01                                                                method = RPK (1)
1-2     00 20                                                             trusted_keys_len = 32
3-34    06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9  spki_hash (SHA-256)
35-36   00 2c                                                             authenticator_len = 44
37-80   302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172    SPKI (DER-encoded)
        f3daa62325af021a68f707511a
81-88   00 00 00 00 70 db d8 80                                           not_after = 1893456000
89-90   08 07                                                             algorithm = Ed25519
91-92   00 40                                                             signature_len = 64
93-156  8ca4021885d35a609b8dcbbd33ee0d09590f77720b4c4c4d74984b67bcc20d    signature (64 bytes)
        7e01a9f72061da2711dcda84cf3073544b05960141a004de11335da2513375d009
```

### 3. Field Details

| Field | Size | Description |
|-------|------|-------------|
| `method` | 1 byte | `0x01` = RPK (raw public key) |
| `trusted_keys_len` | 2 bytes | Length of SPKI hash list |
| `spki_hash` | 32 bytes | SHA-256 of signer's SPKI |
| `authenticator_len` | 2 bytes | Length of public key encoding |
| `authenticator` | variable | DER-encoded SPKI (Ed25519: 44 bytes) |
| `not_after` | 8 bytes | Unix timestamp (big-endian) |
| `algorithm` | 2 bytes | `0x0807` = Ed25519 |
| `signature_len` | 2 bytes | Length of signature |
| `signature` | variable | Ed25519: 64 bytes |

### 4. TLS Handshake Flow

```
Client                                  Server
  │                                       │
  │──── ClientHello ────────────────────▶│
  │     encrypted_client_hello            │
  │     (stale ECH config)                │
  │                                       │
  │◀─── ServerHello + EE ────────────────│
  │     EncryptedExtensions contains:     │
  │       retry_configs with ech_auth     │
  │       ┌─────────────────────────────┐ │
  │       │ method: RPK                 │ │
  │       │ trusted_keys: [spki_hash]   │ │
  │       │ authenticator: SPKI         │ │
  │       │ not_after: 1893456000       │ │
  │       │ algorithm: Ed25519          │ │
  │       │ signature: <64 bytes>       │ │
  │       └─────────────────────────────┘ │
  │                                       │
  │  ┌──────────────────────────────┐     │
  │  │ Client verification:         │     │
  │  │ 1. spki_hash ∈ trusted_keys? │     │
  │  │ 2. not_after > now?          │     │
  │  │ 3. signature valid?          │     │
  │  └──────────────────────────────┘     │
  │                                       │
  │──── ClientHello ────────────────────▶│
  │     encrypted_client_hello            │
  │     (verified new config)             │
  │                                       │
  │◀─── ServerHello ─────────────────────│
  │     [ECH accepted]                    │
  │                                       │
```

### 5. Cross-Implementation Verification

**Rust signs → Go verifies:**

```bash
# Generate vector with Rust
cd rust
cargo run --release --bin gen-test-vector > ../vector.json

# Extract values
SPKI_HASH=$(cat ../vector.json | jq -r '.spki_hash_hex')
ECH_AUTH=$(cat ../vector.json | jq -r '.ech_auth_encoded_hex')

# Convert to binary
echo "$ECH_AUTH" | xxd -r -p > ../signed.bin

# Verify with Go
cd ../go
go run ./cmd/ech-auth verify --config ../signed.bin --trust-anchor "$SPKI_HASH"
```

Output:
```
Parsed ECH Auth extension:
  Method: 1 (RPK)
  Algorithm: 0x0807
  Not after: 1893456000 (2030-01-01T00:00:00Z)
  Signature: 64 bytes
  Trusted keys: 1

VERIFICATION: Structure valid, not expired
```

**Go signs → Rust verifies:**

```bash
# Generate key with Go
cd go
go run ./cmd/ech-auth generate --algorithm ed25519 --output key.json
SPKI_HASH=$(cat key.json | jq -r '.spki_hash_hex')

# Sign with Go (needs config.bin)
echo "test ECH config" > config.bin
go run ./cmd/ech-auth sign --key key.json --config config.bin \
    --not-after $(($(date +%s) + 86400)) --output signed.bin

# Convert to hex for Rust
SIGNED_HEX=$(xxd -p signed.bin | tr -d '\n')
CONFIG_HEX=$(xxd -p config.bin | tr -d '\n')

# Verify with Rust
cd ../rust
echo "$SIGNED_HEX" | cargo run --release --bin ech-verify -- \
    --config-tbs "$CONFIG_HEX" --trusted-key "$SPKI_HASH"
```

## Signature Computation

The signature is computed over:

```
struct {
    opaque context_string<0..255> = "ECH Auth Binding";
    opaque echconfig_tbs<1..2^16-1>;  // ECHConfig without ech_auth extension
    uint64 not_after;
} SignedContent;
```

This binds the signature to:
1. A domain separator ("ECH Auth Binding")
2. The specific ECHConfig being authenticated
3. The expiration timestamp

## Security Properties

- **Authenticity**: Only the holder of the signing key can create valid signatures
- **Freshness**: `not_after` prevents replay of stale configs
- **Binding**: Signature covers the specific ECHConfig, preventing substitution
- **Trust anchor pinning**: Client must have pre-configured trust (SPKI hash or root CA)
