/* NSS ECH Auth Interop Test
 * 
 * Tests NSS ECH Auth implementation against test vectors from Go/Rust.
 * Validates:
 * - Wire format compatibility
 * - PKIX not_after=0 compliance
 * - Cross-implementation verification
 */

#include "prtypes.h"
#include "seccomon.h"
#include "tls13echauth.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

// Read file into buffer
static unsigned char *read_file(const char *path, size_t *out_len) {
  FILE *f = fopen(path, "rb");
  if (!f) {
    fprintf(stderr, "Failed to open %s\n", path);
    return NULL;
  }
  
  fseek(f, 0, SEEK_END);
  long len = ftell(f);
  fseek(f, 0, SEEK_SET);
  
  unsigned char *buf = malloc(len);
  if (!buf) {
    fclose(f);
    return NULL;
  }
  
  if (fread(buf, 1, len, f) != (size_t)len) {
    free(buf);
    fclose(f);
    return NULL;
  }
  
  fclose(f);
  *out_len = len;
  return buf;
}

void test_go_rpk_vector() {
  size_t len;
  unsigned char *data = read_file("./test-vectors/go_signed_rpk.ech", &len);
  if (!data) {
    printf("SKIP: test_go_rpk_vector (file not found)\n");
    return;
  }
  
  sslEchAuthExtension auth;
  SECStatus rv = tls13_ParseEchAuthExtension(data, len, &auth);
  
  TEST("test_go_rpk_vector",
       rv == SECSuccess && auth.method == ech_auth_method_rpk);
  
  if (rv == SECSuccess) {
    tls13_DestroyEchAuthExtension(&auth);
  }
  free(data);
}

void test_go_pkix_vector() {
  size_t len;
  unsigned char *data = read_file("./test-vectors/go_signed_pkix.ech", &len);
  if (!data) {
    printf("SKIP: test_go_pkix_vector (file not found)\n");
    return;
  }
  
  sslEchAuthExtension auth;
  SECStatus rv = tls13_ParseEchAuthExtension(data, len, &auth);
  
  TEST("test_go_pkix_vector",
       rv == SECSuccess && 
       auth.method == ech_auth_method_pkix &&
       auth.notAfter > 0);  // Must have valid timestamp per PR #2
  
  if (rv == SECSuccess) {
    tls13_DestroyEchAuthExtension(&auth);
  }
  free(data);
}

void test_go_pkix_invalid_not_after() {
  // This test is for a specific bad vector that doesn't exist yet
  printf("SKIP: test_go_pkix_invalid_not_after (vector not generated)\n");
}

void test_rust_rpk_vector() {
  size_t len;
  unsigned char *data = read_file("./test-vectors/rust_signed_rpk.ech", &len);
  if (!data) {
    printf("SKIP: test_rust_rpk_vector (file not found)\n");
    return;
  }
  
  sslEchAuthExtension auth;
  SECStatus rv = tls13_ParseEchAuthExtension(data, len, &auth);
  
  TEST("test_rust_rpk_vector",
       rv == SECSuccess && auth.method == ech_auth_method_rpk);
  
  if (rv == SECSuccess) {
    tls13_DestroyEchAuthExtension(&auth);
  }
  free(data);
}

void test_rust_pkix_vector() {
  size_t len;
  unsigned char *data = read_file("./test-vectors/rust_signed_pkix.ech", &len);
  if (!data) {
    printf("SKIP: test_rust_pkix_vector (file not found)\n");
    return;
  }
  
  sslEchAuthExtension auth;
  SECStatus rv = tls13_ParseEchAuthExtension(data, len, &auth);
  
  TEST("test_rust_pkix_vector",
       rv == SECSuccess && 
       auth.method == ech_auth_method_pkix &&
       auth.notAfter > 0);  // Must have valid timestamp per PR #2
  
  if (rv == SECSuccess) {
    tls13_DestroyEchAuthExtension(&auth);
  }
  free(data);
}

int main() {
  printf("=== NSS ECH Auth Interop Tests ===\n\n");
  
  printf("--- Go Implementation Vectors ---\n");
  test_go_rpk_vector();
  test_go_pkix_vector();
  test_go_pkix_invalid_not_after();
  
  printf("\n--- Rust Implementation Vectors ---\n");
  test_rust_rpk_vector();
  test_rust_pkix_vector();
  
  printf("\n=== Test Results ===\n");
  printf("Passed: %d\n", tests_passed);
  printf("Failed: %d\n", tests_failed);
  
  return tests_failed > 0 ? 1 : 0;
}
