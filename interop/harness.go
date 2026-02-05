package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const version = "1.0.0"

// TestVector represents a single interop test case
type TestVector struct {
	Name         string            `json:"name"`
	Description  string            `json:"description,omitempty"`
	Method       string            `json:"method"` // "rpk" or "pkix"
	TestType     string            `json:"test_type"`
	ECHConfig    string            `json:"ech_config"`
	SigningKey   *SigningKey       `json:"signing_key,omitempty"`
	Signature    *Signature        `json:"signature"`
	Verification *Verification     `json:"verification"`
	Expected     ExpectedResult    `json:"expected"`
	Source       string            `json:"source,omitempty"`
}

type SigningKey struct {
	Algorithm      string `json:"algorithm"`
	PrivateKeyHex  string `json:"private_key_hex"`
	SPKIHex        string `json:"spki_hex"`
}

type Signature struct {
	Algorithm         uint16 `json:"algorithm"`
	NotAfter          uint64 `json:"not_after"`
	AuthenticatorHex  string `json:"authenticator_hex"`
	SignatureHex      string `json:"signature_hex"`
}

type Verification struct {
	CurrentTime  uint64       `json:"current_time"`
	TrustAnchors TrustAnchors `json:"trust_anchors"`
}

type TrustAnchors struct {
	RPKSPKIHashes []string `json:"rpk_spki_hashes,omitempty"`
	PKIXRoots     []string `json:"pkix_roots,omitempty"`
}

type ExpectedResult struct {
	Valid              bool   `json:"valid"`
	ErrorContains      string `json:"error_contains,omitempty"`
	SPKIHashHex        string `json:"spki_hash_hex,omitempty"`
	SignedECHConfigHex string `json:"signed_ech_config_hex,omitempty"`
}

// TestVectorFile represents the root JSON structure
type TestVectorFile struct {
	Version     string       `json:"version"`
	TestVectors []TestVector `json:"test_vectors"`
}

// Implementation represents a testable ECH Auth implementation
type Implementation struct {
	Name       string
	VerifyCmd  []string // Command to verify a signature
	SignCmd    []string // Command to sign (optional)
	WorkingDir string
}

type TestResult struct {
	TestName       string
	Implementation string
	Passed         bool
	Error          string
	Duration       time.Duration
}

func main() {
	var (
		vectorFile = flag.String("vectors", "test-vectors/interop.json", "Path to test vector JSON file")
		implFilter = flag.String("impl", "", "Only test specific implementation (rust/go/nss)")
		testFilter = flag.String("test", "", "Only run tests matching this name substring")
		verbose    = flag.Bool("v", false, "Verbose output")
		listTests  = flag.Bool("list", false, "List available tests and exit")
	)
	flag.Parse()

	// Load test vectors
	data, err := os.ReadFile(*vectorFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading test vectors: %v\n", err)
		os.Exit(1)
	}

	var tvFile TestVectorFile
	if err := json.Unmarshal(data, &tvFile); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing test vectors: %v\n", err)
		os.Exit(1)
	}

	if *listTests {
		fmt.Printf("Test vectors from %s (version %s):\n", *vectorFile, tvFile.Version)
		for i, tv := range tvFile.TestVectors {
			fmt.Printf("  %d. %s (%s, %s)\n", i+1, tv.Name, tv.Method, tv.TestType)
			if tv.Description != "" {
				fmt.Printf("     %s\n", tv.Description)
			}
		}
		return
	}

	// Discover implementations
	impls := discoverImplementations()
	if *implFilter != "" {
		filtered := []Implementation{}
		for _, impl := range impls {
			if strings.Contains(strings.ToLower(impl.Name), strings.ToLower(*implFilter)) {
				filtered = append(filtered, impl)
			}
		}
		impls = filtered
	}

	if len(impls) == 0 {
		fmt.Fprintf(os.Stderr, "No implementations found\n")
		os.Exit(1)
	}

	fmt.Printf("ECH Auth Interop Test Harness v%s\n", version)
	fmt.Printf("Test vectors: %s (version %s)\n", *vectorFile, tvFile.Version)
	fmt.Printf("Implementations: %d\n", len(impls))
	fmt.Printf("Test vectors: %d\n\n", len(tvFile.TestVectors))

	// Run tests
	var results []TestResult
	for _, impl := range impls {
		fmt.Printf("Testing %s:\n", impl.Name)
		for _, tv := range tvFile.TestVectors {
			if *testFilter != "" && !strings.Contains(tv.Name, *testFilter) {
				continue
			}

			result := runTest(impl, tv, *verbose)
			results = append(results, result)

			status := "✓ PASS"
			if !result.Passed {
				status = "✗ FAIL"
			}
			fmt.Printf("  %s %s (%dms)\n", status, tv.Name, result.Duration.Milliseconds())
			if !result.Passed && result.Error != "" {
				fmt.Printf("      Error: %s\n", result.Error)
			}
		}
		fmt.Println()
	}

	// Summary
	passed := 0
	failed := 0
	for _, r := range results {
		if r.Passed {
			passed++
		} else {
			failed++
		}
	}

	fmt.Printf("=== Summary ===\n")
	fmt.Printf("Total: %d tests\n", len(results))
	fmt.Printf("Passed: %d\n", passed)
	fmt.Printf("Failed: %d\n", failed)

	if failed > 0 {
		os.Exit(1)
	}
}

func discoverImplementations() []Implementation {
	var impls []Implementation

	// Check for Go implementation
	if _, err := os.Stat("go/go.mod"); err == nil {
		impls = append(impls, Implementation{
			Name:       "Go",
			VerifyCmd:  []string{"go", "run", "./cmd/echauth-verify"},
			SignCmd:    []string{"go", "run", "./cmd/echauth-sign"},
			WorkingDir: "go",
		})
	}

	// Check for Rust implementation
	if _, err := os.Stat("rust/Cargo.toml"); err == nil {
		impls = append(impls, Implementation{
			Name:       "Rust",
			VerifyCmd:  []string{"cargo", "run", "--quiet", "--bin", "ech-verify", "--"},
			SignCmd:    []string{"cargo", "run", "--quiet", "--bin", "ech-sign", "--"},
			WorkingDir: "rust",
		})
	}

	// Check for NSS implementation
	if _, err := os.Stat("nss/echauth_client"); err == nil {
		impls = append(impls, Implementation{
			Name:       "NSS",
			VerifyCmd:  []string{"./echauth_client"},
			WorkingDir: "nss",
		})
	}

	return impls
}

func runTest(impl Implementation, tv TestVector, verbose bool) TestResult {
	start := time.Now()
	result := TestResult{
		TestName:       tv.Name,
		Implementation: impl.Name,
		Passed:         false,
	}

	// Create temporary test file
	tmpDir, err := os.MkdirTemp("", "echauth-test-*")
	if err != nil {
		result.Error = fmt.Sprintf("failed to create temp dir: %v", err)
		result.Duration = time.Since(start)
		return result
	}
	defer os.RemoveAll(tmpDir)

	// Write signed ECHConfig to file
	signedConfig, err := buildSignedConfig(tv)
	if err != nil {
		result.Error = fmt.Sprintf("failed to build signed config: %v", err)
		result.Duration = time.Since(start)
		return result
	}

	configPath := filepath.Join(tmpDir, "test.ech")
	if err := os.WriteFile(configPath, signedConfig, 0644); err != nil {
		result.Error = fmt.Sprintf("failed to write config: %v", err)
		result.Duration = time.Since(start)
		return result
	}

	// Build verification command (implementation-specific)
	cmd := buildVerifyCommand(impl, tv, configPath)
	if cmd == nil {
		result.Error = "implementation does not support verification"
		result.Duration = time.Since(start)
		return result
	}

	// Run the test
	output, err := cmd.CombinedOutput()
	if verbose {
		fmt.Printf("    Command: %v\n", cmd.Args)
		fmt.Printf("    Output: %s\n", string(output))
	}

	// Check result
	if tv.Expected.Valid {
		if err != nil {
			result.Error = fmt.Sprintf("expected success but got error: %v\nOutput: %s", err, string(output))
		} else {
			result.Passed = true
		}
	} else {
		if err == nil {
			result.Error = "expected failure but verification succeeded"
		} else {
			// Check error message if specified
			if tv.Expected.ErrorContains != "" {
				if strings.Contains(string(output), tv.Expected.ErrorContains) || strings.Contains(err.Error(), tv.Expected.ErrorContains) {
					result.Passed = true
				} else {
					result.Error = fmt.Sprintf("error doesn't contain expected string '%s': %v\nOutput: %s", tv.Expected.ErrorContains, err, string(output))
				}
			} else {
				result.Passed = true
			}
		}
	}

	result.Duration = time.Since(start)
	return result
}

func buildSignedConfig(tv TestVector) ([]byte, error) {
	// If expected signed config is provided, use it
	if tv.Expected.SignedECHConfigHex != "" {
		return hex.DecodeString(tv.Expected.SignedECHConfigHex)
	}

	// Otherwise, we'd need to build it from components
	// For now, this is a placeholder - implementations should provide pre-signed configs
	return nil, fmt.Errorf("signed config not provided in test vector")
}

func buildVerifyCommand(impl Implementation, tv TestVector, configPath string) *exec.Cmd {
	// This is a simplified version - actual implementations will have different CLI interfaces
	// For now, assume a common interface:
	// <cmd> verify --config <file> --time <unix_timestamp> --trust-anchor <spki_hash|cert>

	args := append([]string{}, impl.VerifyCmd...)
	args = append(args, "verify", "--config", configPath)

	if tv.Verification != nil {
		args = append(args, "--time", fmt.Sprintf("%d", tv.Verification.CurrentTime))

		if tv.Method == "rpk" && len(tv.Verification.TrustAnchors.RPKSPKIHashes) > 0 {
			for _, hash := range tv.Verification.TrustAnchors.RPKSPKIHashes {
				args = append(args, "--trust-anchor", hash)
			}
		}
	}

	cmd := exec.Command(args[0], args[1:]...)
	if impl.WorkingDir != "" {
		cmd.Dir = impl.WorkingDir
	}

	return cmd
}
