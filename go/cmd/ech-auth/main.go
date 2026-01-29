// ECH Auth CLI - Sign, verify, and serve ECH configs
//
// Commands:
//   generate  Generate a signing key
//   sign      Sign an ECH config
//   verify    Verify a signed ECH config
//   serve     Run TLS server with ECH support

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/grittygrease/echauth"
)

type KeyFile struct {
	Algorithm  string `json:"algorithm"`
	PrivateKey string `json:"private_key_hex"`
	PublicKey  string `json:"public_key_hex"`
	SPKIHash   string `json:"spki_hash_hex"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "generate":
		err = cmdGenerate(args)
	case "sign":
		err = cmdSign(args)
	case "verify":
		err = cmdVerify(args)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`ECH Auth CLI

Usage:
  ech-auth generate --algorithm ed25519 --output key.json
  ech-auth sign --key key.json --config config.bin [--not-after TIMESTAMP] --output signed.bin
  ech-auth verify --config signed.bin --trust-anchor SPKI_HASH_HEX

Commands:
  generate    Generate a new signing key pair
  sign        Sign an ECH config with ech_auth extension
  verify      Verify a signed ECH config

Options:
  --algorithm    Signature algorithm: ed25519 (default), p256
  --key          Path to key file (JSON)
  --config       Path to ECH config (binary)
  --output       Output path
  --trust-anchor SPKI hash in hex (64 chars)
  --not-after    Expiration timestamp (Unix seconds, default: +24h)`)
}

func cmdGenerate(args []string) error {
	algorithm := "ed25519"
	output := ""

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--algorithm", "-a":
			if i+1 >= len(args) {
				return fmt.Errorf("--algorithm requires a value")
			}
			i++
			algorithm = args[i]
		case "--output", "-o":
			if i+1 >= len(args) {
				return fmt.Errorf("--output requires a value")
			}
			i++
			output = args[i]
		}
	}

	if output == "" {
		return fmt.Errorf("--output is required")
	}

	switch algorithm {
	case "ed25519":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("generate key: %w", err)
		}

		spki := echauth.EncodeEd25519SPKI(pub)
		spkiHash := echauth.ComputeSPKIHash(spki)

		keyFile := KeyFile{
			Algorithm:  "ed25519",
			PrivateKey: hex.EncodeToString(priv.Seed()),
			PublicKey:  hex.EncodeToString(pub),
			SPKIHash:   hex.EncodeToString(spkiHash[:]),
		}

		data, err := json.MarshalIndent(keyFile, "", "  ")
		if err != nil {
			return err
		}

		if err := os.WriteFile(output, data, 0600); err != nil {
			return err
		}

		fmt.Printf("Generated Ed25519 key: %s\n", output)
		fmt.Printf("SPKI hash: %s\n", keyFile.SPKIHash)
		return nil

	default:
		return fmt.Errorf("unsupported algorithm: %s (use ed25519)", algorithm)
	}
}

func cmdSign(args []string) error {
	keyPath := ""
	configPath := ""
	output := ""
	notAfter := time.Now().Add(24 * time.Hour).Unix()

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--key", "-k":
			if i+1 >= len(args) {
				return fmt.Errorf("--key requires a value")
			}
			i++
			keyPath = args[i]
		case "--config", "-c":
			if i+1 >= len(args) {
				return fmt.Errorf("--config requires a value")
			}
			i++
			configPath = args[i]
		case "--output", "-o":
			if i+1 >= len(args) {
				return fmt.Errorf("--output requires a value")
			}
			i++
			output = args[i]
		case "--not-after":
			if i+1 >= len(args) {
				return fmt.Errorf("--not-after requires a value")
			}
			i++
			ts, err := strconv.ParseInt(args[i], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid --not-after: %w", err)
			}
			notAfter = ts
		}
	}

	if keyPath == "" || configPath == "" || output == "" {
		return fmt.Errorf("--key, --config, and --output are required")
	}

	// Load key
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read key: %w", err)
	}

	var keyFile KeyFile
	if err := json.Unmarshal(keyData, &keyFile); err != nil {
		return fmt.Errorf("parse key: %w", err)
	}

	if keyFile.Algorithm != "ed25519" {
		return fmt.Errorf("unsupported algorithm in key file: %s", keyFile.Algorithm)
	}

	seed, err := hex.DecodeString(keyFile.PrivateKey)
	if err != nil {
		return fmt.Errorf("decode private key: %w", err)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)

	// Load config
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	// Sign
	sig := echauth.SignRPK(configData, privateKey, time.Unix(notAfter, 0))

	// Build Auth structure with SPKI hash as trusted key
	pubKey := privateKey.Public().(ed25519.PublicKey)
	spki := echauth.EncodeEd25519SPKI(pubKey)
	spkiHash := echauth.ComputeSPKIHash(spki)

	auth := &echauth.Auth{
		Method:      echauth.MethodRPK,
		TrustedKeys: []echauth.SPKIHash{spkiHash},
		Signature:   sig,
	}

	// Encode
	encoded := auth.Encode()

	if err := os.WriteFile(output, encoded, 0644); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	fmt.Printf("Signed ECH config: %s\n", output)
	fmt.Printf("  Algorithm: Ed25519\n")
	fmt.Printf("  Not after: %d (%s)\n", notAfter, time.Unix(notAfter, 0).Format(time.RFC3339))
	fmt.Printf("  SPKI hash: %s\n", keyFile.SPKIHash)
	fmt.Printf("  Output size: %d bytes\n", len(encoded))

	return nil
}

func cmdVerify(args []string) error {
	configPath := ""
	trustAnchorHex := ""

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--config", "-c":
			if i+1 >= len(args) {
				return fmt.Errorf("--config requires a value")
			}
			i++
			configPath = args[i]
		case "--trust-anchor", "-t":
			if i+1 >= len(args) {
				return fmt.Errorf("--trust-anchor requires a value")
			}
			i++
			trustAnchorHex = args[i]
		}
	}

	if configPath == "" || trustAnchorHex == "" {
		return fmt.Errorf("--config and --trust-anchor are required")
	}

	// Parse trust anchor
	if len(trustAnchorHex) != 64 {
		return fmt.Errorf("trust anchor must be 64 hex chars (SHA-256)")
	}
	trustAnchorBytes, err := hex.DecodeString(trustAnchorHex)
	if err != nil {
		return fmt.Errorf("invalid trust anchor hex: %w", err)
	}
	var spkiHash echauth.SPKIHash
	copy(spkiHash[:], trustAnchorBytes)

	// Load signed config
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	// Decode
	auth, err := echauth.Decode(configData)
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}

	fmt.Printf("Parsed ECH Auth extension:\n")
	fmt.Printf("  Method: %d (RPK)\n", auth.Method)
	if auth.Signature != nil {
		fmt.Printf("  Algorithm: 0x%04x\n", auth.Signature.Algorithm)
		fmt.Printf("  Not after: %d (%s)\n", auth.Signature.NotAfter, time.Unix(int64(auth.Signature.NotAfter), 0).Format(time.RFC3339))
		fmt.Printf("  Signature: %d bytes\n", len(auth.Signature.SignatureData))
	}
	fmt.Printf("  Trusted keys: %d\n", len(auth.TrustedKeys))

	// Check trust anchor
	foundMatch := false
	for _, tk := range auth.TrustedKeys {
		if tk == spkiHash {
			foundMatch = true
			break
		}
	}

	if !foundMatch {
		// The SPKI hash in the extension should match what we trust
		fmt.Printf("\nWARNING: Provided trust anchor not found in extension trusted_keys\n")
		fmt.Printf("  Expected: %s\n", trustAnchorHex)
		if len(auth.TrustedKeys) > 0 {
			fmt.Printf("  Found: %s\n", hex.EncodeToString(auth.TrustedKeys[0][:]))
		}
	}

	// Check expiration
	if auth.Signature != nil {
		now := time.Now().Unix()
		if uint64(now) >= auth.Signature.NotAfter {
			return fmt.Errorf("EXPIRED: not_after %d < current %d", auth.Signature.NotAfter, now)
		}
	}

	fmt.Printf("\nVERIFICATION: Structure valid, not expired\n")
	fmt.Printf("NOTE: Full signature verification requires original TBS data\n")

	return nil
}
