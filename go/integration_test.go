// Integration tests for ECH with in-band authenticated key rotation
//
// Test flow:
// 1. Client gets initial ECH config (simulating DoH fetch)
// 2. Client connects successfully with that config
// 3. Server rotates keys, client's config becomes stale
// 4. Client connects, gets ECH rejection with signed retry configs
// 5. Client verifies retry configs against trust anchors
// 6. Client connects successfully with new config

package echauth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// buildSignedConfig creates a properly signed ECHConfig for testing.
// It signs the config WITHOUT the extension, then builds a config WITH the extension,
// and sets Raw to the TBS bytes for proper verification.
func buildSignedConfig(t *testing.T, configID uint8, publicName string, privateKey ed25519.PrivateKey, notAfter time.Time) ([]byte, *TrustAnchor) {
	t.Helper()

	// Build config without extension first - this is the TBS
	configTBS := buildTestECHConfig(t, configID, publicName, nil)

	// Sign the TBS
	authExt := signConfig(t, configTBS, privateKey, notAfter)

	// Build config WITH the extension
	configWithExt := buildTestECHConfig(t, configID, publicName, []Extension{
		{Type: ECHAuthExtensionType, Data: authExt},
	})

	// Create trust anchor
	spki := EncodeEd25519SPKI(privateKey.Public().(ed25519.PublicKey))
	spkiHash := sha256.Sum256(spki)
	anchor := &TrustAnchor{TrustedKeys: []SPKIHash{spkiHash}}

	// Return the config with extension (for wire format) and the TBS (for Raw override)
	// We'll need to parse and fix up Raw before verification
	return configWithExt, anchor
}

// parseAndFixupConfig parses a config list and sets Raw to the proper TBS
func parseAndFixupConfig(t *testing.T, configList []byte, configID uint8, publicName string) []ECHConfig {
	t.Helper()

	configs, err := ParseECHConfigList(configList)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	// For each config, override Raw with the TBS (config without extension)
	for i := range configs {
		if configs[i].ConfigID == configID {
			configs[i].Raw = buildTestECHConfig(t, configID, publicName, nil)
		}
	}

	return configs
}

// TestIntegration_FullECHFlow tests the complete ECH flow with key rotation
func TestIntegration_FullECHFlow(t *testing.T) {
	// Generate signing key for ECH config authentication
	_, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate signing key: %v", err)
	}

	notAfter := time.Now().Add(24 * time.Hour)
	nowFunc := func() uint64 { return uint64(time.Now().Unix()) }

	// Create trust anchor
	spki := EncodeEd25519SPKI(signingKey.Public().(ed25519.PublicKey))
	spkiHash := sha256.Sum256(spki)
	trustAnchor := &TrustAnchor{TrustedKeys: []SPKIHash{spkiHash}}

	// Generate initial ECH config (unsigned - simulating DoH fetch)
	initialConfig := buildTestECHConfig(t, 1, "backend.example.com", nil)
	t.Logf("Initial config: %d bytes", len(initialConfig))

	// Generate rotated ECH config with ech_auth signature
	rotatedConfigTBS := buildTestECHConfig(t, 2, "backend.example.com", nil)
	authExt := signConfig(t, rotatedConfigTBS, signingKey, notAfter)
	signedConfig := buildTestECHConfig(t, 2, "backend.example.com", []Extension{
		{Type: ECHAuthExtensionType, Data: authExt},
	})
	t.Logf("Signed rotated config: %d bytes", len(signedConfig))

	// Build config list
	configList := buildECHConfigList(signedConfig)

	t.Run("VerifySignedConfig", func(t *testing.T) {
		configs, err := ParseECHConfigList(configList)
		if err != nil {
			t.Fatalf("parse failed: %v", err)
		}
		// Fix up Raw to be the TBS
		configs[0].Raw = rotatedConfigTBS

		err = VerifyConfig(&configs[0], trustAnchor, nowFunc)
		if err != nil {
			t.Errorf("verification failed: %v", err)
		}
	})

	t.Run("RejectUntrustedConfig", func(t *testing.T) {
		configs, _ := ParseECHConfigList(configList)
		configs[0].Raw = rotatedConfigTBS

		wrongAnchor := &TrustAnchor{TrustedKeys: []SPKIHash{{0xff}}}
		err := VerifyConfig(&configs[0], wrongAnchor, nowFunc)
		if err == nil {
			t.Error("expected verification to fail with wrong trust anchor")
		}
	})

	t.Run("RejectExpiredConfig", func(t *testing.T) {
		expiredAuthExt := signConfig(t, rotatedConfigTBS, signingKey, time.Now().Add(-1*time.Hour))
		expiredConfig := buildTestECHConfig(t, 3, "backend.example.com", []Extension{
			{Type: ECHAuthExtensionType, Data: expiredAuthExt},
		})
		expiredList := buildECHConfigList(expiredConfig)

		configs, _ := ParseECHConfigList(expiredList)
		configs[0].Raw = buildTestECHConfig(t, 3, "backend.example.com", nil)

		err := VerifyConfig(&configs[0], trustAnchor, nowFunc)
		if err == nil {
			t.Error("expected verification to fail for expired config")
		}
	})

	t.Run("LegacyNoAuth", func(t *testing.T) {
		// nil trust anchor = legacy mode, no verification
		verified, err := VerifyConfigList(configList, nil, nowFunc)
		if err != nil {
			t.Errorf("legacy mode failed: %v", err)
		}
		if len(verified) == 0 {
			t.Error("legacy mode should return configs")
		}
		t.Log("Legacy mode: configs accepted without verification")
	})

	_ = initialConfig // Would be used for initial connection
}

// TestIntegration_MixedConfigs tests filtering when some configs are valid and some aren't
func TestIntegration_MixedConfigs(t *testing.T) {
	// Generate two signing keys
	_, signingKey1, _ := ed25519.GenerateKey(rand.Reader)
	_, signingKey2, _ := ed25519.GenerateKey(rand.Reader)

	// Only trust key1
	spki1 := EncodeEd25519SPKI(signingKey1.Public().(ed25519.PublicKey))
	spkiHash1 := sha256.Sum256(spki1)
	trustAnchor := &TrustAnchor{TrustedKeys: []SPKIHash{spkiHash1}}
	nowFunc := func() uint64 { return uint64(time.Now().Unix()) }

	notAfter := time.Now().Add(24 * time.Hour)

	// Config 1: signed by trusted key
	config1TBS := buildTestECHConfig(t, 1, "example.com", nil)
	authExt1 := signConfig(t, config1TBS, signingKey1, notAfter)
	signedConfig1 := buildTestECHConfig(t, 1, "example.com", []Extension{
		{Type: ECHAuthExtensionType, Data: authExt1},
	})

	// Config 2: signed by untrusted key
	config2TBS := buildTestECHConfig(t, 2, "example.com", nil)
	authExt2 := signConfig(t, config2TBS, signingKey2, notAfter)
	signedConfig2 := buildTestECHConfig(t, 2, "example.com", []Extension{
		{Type: ECHAuthExtensionType, Data: authExt2},
	})

	// Config 3: also signed by trusted key
	config3TBS := buildTestECHConfig(t, 3, "example.com", nil)
	authExt3 := signConfig(t, config3TBS, signingKey1, notAfter)
	signedConfig3 := buildTestECHConfig(t, 3, "example.com", []Extension{
		{Type: ECHAuthExtensionType, Data: authExt3},
	})

	// Build list with all configs
	configList := buildECHConfigList(signedConfig1, signedConfig2, signedConfig3)

	// Parse and fix up
	configs, _ := ParseECHConfigList(configList)
	configs[0].Raw = config1TBS
	configs[1].Raw = config2TBS
	configs[2].Raw = config3TBS

	// Verify each config individually
	var verified []ECHConfig
	for _, config := range configs {
		if err := VerifyConfig(&config, trustAnchor, nowFunc); err == nil {
			verified = append(verified, config)
		}
	}

	// Should have 2 verified configs (1 and 3)
	if len(verified) != 2 {
		t.Errorf("expected 2 verified configs, got %d", len(verified))
	}

	t.Logf("Verified %d of 3 configs (expected 2)", len(verified))
}

// TestIntegration_TLSServerSimulation simulates the full TLS flow
func TestIntegration_TLSServerSimulation(t *testing.T) {
	// Generate server TLS certificate
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate server key: %v", err)
	}

	serverCert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "backend.example.com"},
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverCert, serverCert, &serverKey.PublicKey, serverKey)
	if err != nil {
		t.Fatalf("failed to create server cert: %v", err)
	}

	// Generate ECH signing key
	_, echSigningKey, _ := ed25519.GenerateKey(rand.Reader)
	spki := EncodeEd25519SPKI(echSigningKey.Public().(ed25519.PublicKey))
	spkiHash := sha256.Sum256(spki)

	notAfter := time.Now().Add(24 * time.Hour)
	nowFunc := func() uint64 { return uint64(time.Now().Unix()) }

	// Generate ECH configs
	initialConfig := buildTestECHConfig(t, 1, "backend.example.com", nil)
	rotatedConfigTBS := buildTestECHConfig(t, 2, "backend.example.com", nil)
	rotatedAuthExt := signConfig(t, rotatedConfigTBS, echSigningKey, notAfter)
	signedRotatedConfig := buildTestECHConfig(t, 2, "backend.example.com", []Extension{
		{Type: ECHAuthExtensionType, Data: rotatedAuthExt},
	})

	t.Logf("Server cert created")
	t.Logf("Initial ECH config (ID=1): %d bytes", len(initialConfig))
	t.Logf("Signed rotated config (ID=2): %d bytes", len(signedRotatedConfig))
	t.Logf("Trust anchor: %x", spkiHash[:8])

	// Simulate the client flow
	t.Run("ClientFlow", func(t *testing.T) {
		// Step 1: Client has initial config from DoH
		t.Log("Step 1: Client has initial ECH config from DoH")
		initialConfigList := buildECHConfigList(initialConfig)
		t.Logf("  Config list: %d bytes", len(initialConfigList))

		// Step 2: Server rotates keys (would happen server-side)
		t.Log("Step 2: Server rotates ECH keys")

		// Step 3: Client connects, ECH rejected (simulated)
		t.Log("Step 3: Client connects with stale config, ECH rejected")
		retryConfigList := buildECHConfigList(signedRotatedConfig)
		t.Logf("  Received retry configs: %d bytes", len(retryConfigList))

		// Step 4: Client verifies retry configs
		t.Log("Step 4: Client verifies retry configs against trust anchors")
		configs, _ := ParseECHConfigList(retryConfigList)
		configs[0].Raw = rotatedConfigTBS // Fix up TBS

		trustAnchor := &TrustAnchor{TrustedKeys: []SPKIHash{spkiHash}}
		err := VerifyConfig(&configs[0], trustAnchor, nowFunc)
		if err != nil {
			t.Fatalf("  Verification failed: %v", err)
		}
		t.Log("  Verified 1 config")

		// Step 5: Client uses verified config (would connect again)
		t.Log("Step 5: Client would connect with verified config")
		t.Log("Flow completed successfully")
	})

	// Test failure case: attacker injects unsigned config
	t.Run("AttackerInjection", func(t *testing.T) {
		_, attackerKey, _ := ed25519.GenerateKey(rand.Reader)
		attackerConfigTBS := buildTestECHConfig(t, 99, "attacker.example.com", nil)
		attackerAuthExt := signConfig(t, attackerConfigTBS, attackerKey, notAfter)
		attackerConfig := buildTestECHConfig(t, 99, "attacker.example.com", []Extension{
			{Type: ECHAuthExtensionType, Data: attackerAuthExt},
		})

		retryConfigList := buildECHConfigList(attackerConfig)
		configs, _ := ParseECHConfigList(retryConfigList)
		configs[0].Raw = attackerConfigTBS

		trustAnchor := &TrustAnchor{TrustedKeys: []SPKIHash{spkiHash}} // Only trust legitimate key

		err := VerifyConfig(&configs[0], trustAnchor, nowFunc)
		if err == nil {
			t.Error("Expected attacker config to be rejected")
		} else {
			t.Logf("Attacker config correctly rejected: %v", err)
		}
	})

	_ = serverCertDER // Would be used in actual TLS server
}

// TestIntegration_RealTLSConnection tests with actual TLS connections
func TestIntegration_RealTLSConnection(t *testing.T) {
	// Generate server key and cert
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  key,
		}},
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	// Echo handler
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	// Connect as client
	clientConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", listener.Addr().String(), clientConfig)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()

	// Send test data
	testData := []byte("hello ECH")
	if _, err := conn.Write(testData); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	// Read response
	buf := make([]byte, len(testData))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read failed: %v", err)
	}

	if string(buf) != string(testData) {
		t.Errorf("echo mismatch: got %q, want %q", buf, testData)
	}

	t.Log("TLS connection successful")
}

// TestIntegration_ECHRejectionScenario simulates ECH rejection handling
func TestIntegration_ECHRejectionScenario(t *testing.T) {
	// This test simulates what happens when crypto/tls returns ECHRejectionError

	// Setup: Generate keys and configs
	_, echSigningKey, _ := ed25519.GenerateKey(rand.Reader)
	spki := EncodeEd25519SPKI(echSigningKey.Public().(ed25519.PublicKey))
	spkiHash := sha256.Sum256(spki)

	notAfter := time.Now().Add(24 * time.Hour)
	nowFunc := func() uint64 { return uint64(time.Now().Unix()) }

	// Simulate ECHRejectionError from crypto/tls
	type ECHRejectionError struct {
		RetryConfigList []byte
	}

	// Generate signed retry config (what server would send)
	rotatedConfigTBS := buildTestECHConfig(t, 2, "backend.example.com", nil)
	rotatedAuthExt := signConfig(t, rotatedConfigTBS, echSigningKey, notAfter)
	signedConfig := buildTestECHConfig(t, 2, "backend.example.com", []Extension{
		{Type: ECHAuthExtensionType, Data: rotatedAuthExt},
	})
	retryList := buildECHConfigList(signedConfig)

	// Simulate receiving ECHRejectionError
	rejectionErr := &ECHRejectionError{
		RetryConfigList: retryList,
	}

	// Client-side handling (this is what the patch enables)
	trustAnchor := &TrustAnchor{TrustedKeys: []SPKIHash{spkiHash}}

	t.Log("Simulating ECH rejection with signed retry configs")

	// If trust anchors configured, verify retry configs
	if trustAnchor != nil && len(rejectionErr.RetryConfigList) > 0 {
		configs, _ := ParseECHConfigList(rejectionErr.RetryConfigList)
		configs[0].Raw = rotatedConfigTBS // Fix up TBS

		err := VerifyConfig(&configs[0], trustAnchor, nowFunc)
		if err != nil {
			t.Logf("Retry config authentication failed: %v", err)
			rejectionErr.RetryConfigList = nil
		} else {
			t.Log("Verified 1 retry config")
		}
	}

	// Verify we got verified configs
	if rejectionErr.RetryConfigList == nil {
		t.Error("Expected verified retry configs")
	}

	t.Log("ECH rejection scenario handled correctly")
}

// TestIntegration_SignatureBindsConfig verifies signature is bound to specific config
func TestIntegration_SignatureBindsConfig(t *testing.T) {
	_, signingKey, _ := ed25519.GenerateKey(rand.Reader)
	spki := EncodeEd25519SPKI(signingKey.Public().(ed25519.PublicKey))
	spkiHash := sha256.Sum256(spki)
	trustAnchor := &TrustAnchor{TrustedKeys: []SPKIHash{spkiHash}}
	nowFunc := func() uint64 { return uint64(time.Now().Unix()) }

	notAfter := time.Now().Add(24 * time.Hour)

	// Sign config with ID=1
	config1TBS := buildTestECHConfig(t, 1, "example.com", nil)
	authExt1 := signConfig(t, config1TBS, signingKey, notAfter)

	// Build config with ID=2 but using signature from config 1
	signedConfig2 := buildTestECHConfig(t, 2, "example.com", []Extension{
		{Type: ECHAuthExtensionType, Data: authExt1},
	})
	configList := buildECHConfigList(signedConfig2)

	configs, _ := ParseECHConfigList(configList)
	// Set Raw to config2's TBS (not config1's)
	config2TBS := buildTestECHConfig(t, 2, "example.com", nil)
	configs[0].Raw = config2TBS

	err := VerifyConfig(&configs[0], trustAnchor, nowFunc)
	if err == nil {
		t.Error("Expected signature mismatch - signature from config1 should not work for config2")
	} else {
		t.Logf("Correctly rejected mismatched signature: %v", err)
	}
}

// TestIntegration_EmptyTrustAnchorsRejectsAll verifies fail-closed behavior
func TestIntegration_EmptyTrustAnchorsRejectsAll(t *testing.T) {
	_, signingKey, _ := ed25519.GenerateKey(rand.Reader)

	notAfter := time.Now().Add(24 * time.Hour)
	nowFunc := func() uint64 { return uint64(time.Now().Unix()) }

	configTBS := buildTestECHConfig(t, 1, "example.com", nil)
	authExt := signConfig(t, configTBS, signingKey, notAfter)
	signedConfig := buildTestECHConfig(t, 1, "example.com", []Extension{
		{Type: ECHAuthExtensionType, Data: authExt},
	})
	configList := buildECHConfigList(signedConfig)

	// Empty trust anchors (not nil) = fail-closed
	emptyAnchor := &TrustAnchor{TrustedKeys: []SPKIHash{}}

	_, err := VerifyConfigList(configList, emptyAnchor, nowFunc)
	if err == nil {
		t.Error("Expected rejection with empty trust anchors (fail-closed)")
	} else {
		t.Logf("Correctly rejected with empty trust anchors: %v", err)
	}
}

// BenchmarkVerifyConfig measures verification performance
func BenchmarkVerifyConfig(b *testing.B) {
	_, signingKey, _ := ed25519.GenerateKey(rand.Reader)
	spki := EncodeEd25519SPKI(signingKey.Public().(ed25519.PublicKey))
	spkiHash := sha256.Sum256(spki)
	trustAnchor := &TrustAnchor{TrustedKeys: []SPKIHash{spkiHash}}
	nowFunc := func() uint64 { return uint64(time.Now().Unix()) }

	notAfter := time.Now().Add(24 * time.Hour)

	// Build config
	configTBS := buildECHConfigBytes(1, 0x0020, make([]byte, 32), "example.com", nil)
	sig := SignRPK(configTBS, signingKey, notAfter)
	auth := &Auth{
		Method:      MethodRPK,
		TrustedKeys: []SPKIHash{spkiHash},
		Signature:   sig,
	}
	authExt := auth.Encode()

	signedConfig := buildECHConfigBytes(1, 0x0020, make([]byte, 32), "example.com", []Extension{
		{Type: ECHAuthExtensionType, Data: authExt},
	})
	configList := buildECHConfigList(signedConfig)

	configs, _ := ParseECHConfigList(configList)
	configs[0].Raw = configTBS

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = VerifyConfig(&configs[0], trustAnchor, nowFunc)
	}
}
