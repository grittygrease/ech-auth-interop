// Test tool for PR#2 split format (AuthInfo/AuthRetry)
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	echauth "github.com/grittygrease/echauth"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "Usage: split-test <authinfo|authretry> <hex>")
		os.Exit(1)
	}

	cmd := os.Args[1]
	hexData := os.Args[2]

	data, err := hex.DecodeString(hexData)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hex decode error:", err)
		os.Exit(1)
	}

	switch cmd {
	case "authinfo":
		info, err := echauth.DecodeAuthInfo(data)
		if err != nil {
			fmt.Fprintln(os.Stderr, "decode error:", err)
			os.Exit(1)
		}
		fmt.Printf("Method: %v\n", info.Method)
		fmt.Printf("TrustedKeys: %d\n", len(info.TrustedKeys))
		for i, key := range info.TrustedKeys {
			fmt.Printf("  [%d]: %s\n", i, hex.EncodeToString(key[:]))
		}

	case "authretry":
		retry, err := echauth.DecodeAuthRetry(data)
		if err != nil {
			fmt.Fprintln(os.Stderr, "decode error:", err)
			os.Exit(1)
		}
		fmt.Printf("Method: %v\n", retry.Method)
		fmt.Printf("NotAfter: %d\n", retry.NotAfter)
		fmt.Printf("Authenticator: %d bytes\n", len(retry.Authenticator))
		fmt.Printf("Algorithm: 0x%04x\n", retry.Algorithm)
		fmt.Printf("Signature: %d bytes\n", len(retry.Signature))
		hash := retry.SPKIHash()
		fmt.Printf("SPKIHash: %s\n", hex.EncodeToString(hash[:]))

	default:
		fmt.Fprintln(os.Stderr, "Unknown command:", cmd)
		os.Exit(1)
	}
}
