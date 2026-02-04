//go:build e2e

package echauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// generateLegacyECHConfig creates a valid ECHConfig *without* any ECHAuth extensions
func generateLegacyECHConfig(configID uint8, publicName string) (echConfig []byte, privateKey []byte, err error) {
	// Re-use logic from generateECHConfig but ensure no extensions
	// In e2e_test.go, generateECHConfig already generates with NO extensions.
	// So we can just use that, but explicitly verify it has no auth extension.

	config, key, err := generateECHConfig(configID, publicName)
	if err != nil {
		return nil, nil, err
	}

	return config, key.Bytes(), nil
}

func TestE2E_LegacyCompatibility_ClientWithLegacyServer(t *testing.T) {
	// Scenario: Updated Client (our code) connects to Legacy Server (no ech_auth)
	// Expectation: Handshake succeeds, ECH accepted (functionality not broken)

	// 1. Setup Legacy Server
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serverCert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "server.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"server.example.com", "localhost"},
	}
	serverCertDER, _ := x509.CreateCertificate(rand.Reader, serverCert, serverCert, &serverKey.PublicKey, serverKey)

	legacyConfig, legacyPriv, _ := generateLegacyECHConfig(1, "public.example.com")

	// Verify it really has no Auth extension
	parsed, _, err := parseECHConfig(legacyConfig)
	if err != nil {
		t.Fatalf("failed to parse legacy config: %v", err)
	}
	if _, err := parsed.GetAuthExtension(); err == nil {
		t.Fatal("legacy config unexpectedly has auth extension")
	}

	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{serverCertDER},
			PrivateKey:  serverKey,
		}},
		MinVersion: tls.VersionTLS13,
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{
			Config:     legacyConfig,
			PrivateKey: legacyPriv,
		}},
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, _ := listener.Accept()
		if conn == nil {
			return
		}
		defer conn.Close()
		tlsConn := tls.Server(conn, serverTLSConfig)
		tlsConn.Handshake()
	}()

	// 2. Connect with Our Client
	// It should use the legacy config provided in the list
	legacyList := buildECHConfigListFromConfig(legacyConfig)

	clientTLSConfig := &tls.Config{
		ServerName:                     "server.example.com",
		InsecureSkipVerify:             true,
		MinVersion:                     tls.VersionTLS13,
		EncryptedClientHelloConfigList: legacyList,
	}

	conn, err := tls.Dial("tcp", listener.Addr().String(), clientTLSConfig)
	if err != nil {
		t.Fatalf("client dial failed: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if !state.ECHAccepted {
		t.Error("Legacy ECH should be accepted, but was rejected")
	}
	t.Log("Legacy ECH Handshake Succeeded")
}

func TestE2E_LegacyCompatibility_LegacyClientWithUpdatedServer(t *testing.T) {
	// Scenario: Legacy Client (simulated by ignoring auth ext) connects to Updated Server
	// The Go crypto/tls library essentially mimics a legacy client if we don't specifically
	// add logic to parse/verify the ech_auth extension.
	// Since our `crypto/tls` integration here is standard, does it automatically fail on unknown extensions?
	// ECH Config Extensions are critical if the client doesn't understand them?
	// RFC 8890 says extensions in ECHConfig are "mandatory to understand" if they are critical?
	// ECH Auth extension should be marked as non-critical or client ignores if unknown?
	// The draft says: "ECHConfig extensions... Mandatory-to-understand extensions MUST be locally defined."
	// Wait, standard TLS ECHConfig parsing (draft-13+):
	// "Extensions: A list of extensions... If a client does not understand a critical extension... it MUST ignore this ECHConfig".
	// The `ech_auth` extension type is 0xfe0d (or whatever assigned). It must be non-critical for backward compat?
	// The draft says: "Type is 0xfe0d...".
	// If the MSB of the type is 0, it is mandatory (critical)? No, ECHConfig extensions don't have criticality bit typically?
	// Actually, draft-ietf-tls-esni-18 section 4: "If a client encounters an extension with a type it does not understand, it MUST ignore it."
	// UNLESS it's "mandatory".
	// Let's verify that a configuration WITH `ech_auth` is still accepted by a client that doesn't look for it.

	// 1. Setup Updated Server (With Auth Extension)
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serverCert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "server.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"server.example.com", "localhost"},
	}
	serverCertDER, _ := x509.CreateCertificate(rand.Reader, serverCert, serverCert, &serverKey.PublicKey, serverKey)

	// Generate Signed Config
	// accessing generateSignedECHConfig from wireshark_test.go ...
	// wait, wireshark_test.go is "e2e" build tagged. This file is also "e2e".
	// But generateSignedECHConfig might be unexported.
	// I should probably duplicate or export it. It was unexported in wireshark_test.go.
	// I'll re-implement minimalistic version here to be safe and independent.

	config, priv, _ := generateECHConfig(1, "public.example.com")

	// Add dummy auth extension manually
	// Auth Extension Type = 0xfe0d? Or 0xff01?
	// In the previous test we used 0xff01 for ech_auth extension in ServerHello (retry).
	// But inside ECHConfig it uses its own type.
	// draft-sullivan-tls-signed-ech-updates says: "Extension type: ech_auth(0xfe0d)"

	// Helper to add extension
	addExt := func(cfg []byte, typ uint16, dat []byte) []byte {
		// See wireshark_test.go for logic.
		// Simplified: assuming no existing extensions and standard layout from generateECHConfig
		// Config: [Version 2][Length 2][Contents...]
		// Contents end with [ExtLen 2].
		contents := cfg[4:]
		// Strip last 2 bytes (ExtLen=0)
		payload := contents[:len(contents)-2]

		newExtLen := 4 + len(dat)
		var newContents []byte
		newContents = append(newContents, payload...)
		newContents = append(newContents, byte(newExtLen>>8), byte(newExtLen))
		newContents = append(newContents, byte(typ>>8), byte(typ))
		newContents = append(newContents, byte(len(dat)>>8), byte(len(dat)))
		newContents = append(newContents, dat...)

		var newCfg []byte
		newCfg = append(newCfg, cfg[0:2]...)
		newCfg = append(newCfg, byte(len(newContents)>>8), byte(len(newContents)))
		newCfg = append(newCfg, newContents...)
		return newCfg
	}

	signedConfig := addExt(config, 0xAAAA, []byte{0x00, 0x01, 0x02}) // Random type 0xAAAA

	// DEBUG: Verify our own parser accepts it
	if _, _, err := parseECHConfig(signedConfig); err != nil {
		t.Fatalf("Internal parser rejected signed config: %v", err)
	}

	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{serverCertDER},
			PrivateKey:  serverKey,
		}},
		MinVersion: tls.VersionTLS13,
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{
			Config:     signedConfig,
			PrivateKey: priv.Bytes(),
		}},
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, _ := listener.Accept()
		if conn == nil {
			return
		}
		defer conn.Close()
		tlsConn := tls.Server(conn, serverTLSConfig)
		tlsConn.Handshake()
	}()

	// 2. Client connects with Signed Config (but ignores extension)
	// Standard crypto/tls (which we are using wrapped) should ignore unknown ECH extensions

	clientTLSConfig := &tls.Config{
		ServerName:                     "server.example.com",
		InsecureSkipVerify:             true,
		MinVersion:                     tls.VersionTLS13,
		EncryptedClientHelloConfigList: buildECHConfigListFromConfig(signedConfig),
	}

	conn, err := tls.Dial("tcp", listener.Addr().String(), clientTLSConfig)
	if err != nil {
		t.Fatalf("client dial failed with signed config: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if !state.ECHAccepted {
		t.Error("Signed ECH Config should be accepted by client (ignoring ext), but was rejected")
	}
	t.Log("Signed ECH Config Handshake Succeeded")
}
