#include "prtypes.h"
#include "seccomon.h"
#include "tls13echauth.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Test counters
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name, condition) \
  do { \
    if (condition) { \
      printf("PASS: %s\n", name); \
      tests_passed++; \
    } else { \
      printf("FAIL: %s\n", name); \
      tests_failed++; \
    } \
  } while (0)

// =============================================================================
// Basic Parsing Tests
// =============================================================================

void test_parse_empty() {
  sslEchAuthExtension auth;
  SECStatus rv =
      tls13_ParseEchAuthExtension((const unsigned char *)"", 0, &auth);
  TEST("test_parse_empty", rv == SECFailure);
}

void test_parse_rpk_basic() {
  unsigned char data[] = {0, 0, 0}; // method=rpk, no keys, no sig
  sslEchAuthExtension auth;
  SECStatus rv = tls13_ParseEchAuthExtension(data, sizeof(data), &auth);
  TEST("test_parse_rpk_basic",
       rv == SECSuccess && auth.method == ech_auth_method_rpk &&
           auth.hasSignature == PR_FALSE);
  if (rv == SECSuccess) {
    tls13_DestroyEchAuthExtension(&auth);
  }
}

void test_parse_truncated() {
  unsigned char data[] = {0, 0, 1}; // claims 1 key but no data
  sslEchAuthExtension auth;
  SECStatus rv = tls13_ParseEchAuthExtension(data, sizeof(data), &auth);
  TEST("test_parse_truncated", rv == SECFailure);
}

void test_parse_pkix_basic() {
  // PKIX: method=1, not_after=0 (8 bytes), no certs (2 bytes = 0)
  unsigned char data[] = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  sslEchAuthExtension auth;
  SECStatus rv = tls13_ParseEchAuthExtension(data, sizeof(data), &auth);
  TEST("test_parse_pkix_basic",
       rv == SECSuccess && auth.method == ech_auth_method_pkix &&
           auth.hasSignature == PR_FALSE);
  if (rv == SECSuccess) {
    tls13_DestroyEchAuthExtension(&auth);
  }
}

// =============================================================================
// PKIX not_after=0 Compliance Tests (CRITICAL)
// =============================================================================

void test_pkix_not_after_zero_required() {
  // PKIX with not_after=12345 (NON-ZERO) - MUST be rejected per spec
  unsigned char data[] = {
      1,    // method = pkix
      0, 0, 0, 0, 0, 0, 0x30, 0x39, // not_after = 12345 (NON-ZERO!)
      0, 0  // no certs
  };
  sslEchAuthExtension auth;
  SECStatus rv = tls13_ParseEchAuthExtension(data, sizeof(data), &auth);
  TEST("test_pkix_not_after_zero_required", rv == SECFailure);
  // This test validates the critical compliance check in tls13echauth.c
}

void test_pkix_not_after_zero_accepted() {
  // PKIX with not_after=0 - MUST be accepted
  unsigned char data[] = {
      1,    // method = pkix
      0, 0, 0, 0, 0, 0, 0, 0, // not_after = 0 (COMPLIANT)
      0, 0  // no certs
  };
  sslEchAuthExtension auth;
  SECStatus rv = tls13_ParseEchAuthExtension(data, sizeof(data), &auth);
  TEST("test_pkix_not_after_zero_accepted",
       rv == SECSuccess && auth.method == ech_auth_method_pkix);
  if (rv == SECSuccess) {
    tls13_DestroyEchAuthExtension(&auth);
  }
}

// =============================================================================
// RPK Key Count Validation
// =============================================================================

void test_rpk_multiple_keys() {
  // RPK with 2 keys (64 bytes each = 128 total)
  unsigned char data[3 + 64] = {
      0,    // method = rpk
      0, 2  // 2 keys
  };
  // Fill with dummy key data
  memset(data + 3, 0xAA, 64);
  
  sslEchAuthExtension auth;
  SECStatus rv = tls13_ParseEchAuthExtension(data, sizeof(data), &auth);
  TEST("test_rpk_multiple_keys",
       rv == SECSuccess && auth.method == ech_auth_method_rpk &&
           auth.trustedKeysCount == 2);
  if (rv == SECSuccess) {
    tls13_DestroyEchAuthExtension(&auth);
  }
}

void test_rpk_key_length_not_multiple_of_32() {
  // RPK claiming key data that's not a multiple of 32
  unsigned char data[] = {
      0,       // method = rpk
      0, 0,    // key_len = 0
      0, 1, 2  // 3 bytes of junk (not multiple of 32)
  };
  sslEchAuthExtension auth;
  SECStatus rv = tls13_ParseEchAuthExtension(data, sizeof(data), &auth);
  TEST("test_rpk_key_length_not_multiple_of_32", rv == SECFailure);
}

// =============================================================================
// Method Value Validation
// =============================================================================

void test_invalid_method() {
  unsigned char data[] = {99, 0, 0}; // invalid method value
  sslEchAuthExtension auth;
  SECStatus rv = tls13_ParseEchAuthExtension(data, sizeof(data), &auth);
  TEST("test_invalid_method", rv == SECFailure);
}

// =============================================================================
// Signature Block Tests
// =============================================================================

void test_rpk_with_signature() {
  // RPK: method=0, 0 keys, signature present (algorithm=0x0807, 64 bytes)
  unsigned char data[3 + 2 + 2 + 64] = {
      0,       // method = rpk
      0, 0,    // 0 keys
      0x08, 0x07, // Ed25519 algorithm
      0, 64    // 64 byte signature length
  };
  memset(data + 7, 0xBB, 64); // dummy signature
  
  sslEchAuthExtension auth;
  SECStatus rv = tls13_ParseEchAuthExtension(data, sizeof(data), &auth);
  TEST("test_rpk_with_signature",
       rv == SECSuccess && auth.hasSignature == PR_TRUE &&
           auth.signature.algorithm == 0x0807 &&
           auth.signature.signatureLen == 64);
  if (rv == SECSuccess) {
    tls13_DestroyEchAuthExtension(&auth);
  }
}

void test_signature_truncated() {
  // RPK with signature that claims 100 bytes but only has 10
  unsigned char data[3 + 2 + 2 + 10] = {
      0,       // method = rpk
      0, 0,    // 0 keys
      0x08, 0x07, // Ed25519 algorithm
      0, 100   // claims 100 bytes but only 10 follow
  };
  memset(data + 7, 0xCC, 10);
  
  sslEchAuthExtension auth;
  SECStatus rv = tls13_ParseEchAuthExtension(data, sizeof(data), &auth);
  TEST("test_signature_truncated", rv == SECFailure);
}

// =============================================================================
// Main Test Runner
// =============================================================================

int main() {
  printf("=== ECH Auth NSS Implementation Tests ===\n\n");
  
  printf("--- Basic Parsing ---\n");
  test_parse_empty();
  test_parse_rpk_basic();
  test_parse_truncated();
  test_parse_pkix_basic();
  
  printf("\n--- PKIX not_after=0 Compliance (CRITICAL) ---\n");
  test_pkix_not_after_zero_required();
  test_pkix_not_after_zero_accepted();
  
  printf("\n--- RPK Key Validation ---\n");
  test_rpk_multiple_keys();
  test_rpk_key_length_not_multiple_of_32();
  
  printf("\n--- Method Validation ---\n");
  test_invalid_method();
  
  printf("\n--- Signature Block Parsing ---\n");
  test_rpk_with_signature();
  test_signature_truncated();
  
  printf("\n=== Test Results ===\n");
  printf("Passed: %d\n", tests_passed);
  printf("Failed: %d\n", tests_failed);
  
  return tests_failed > 0 ? 1 : 0;
}
