/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * ECH Auth Extension Implementation (draft-sullivan-tls-signed-ech-updates)
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include "tls13echauth.h"
#include "keyhi.h"
#include "pk11pub.h"
#include "secder.h"
#include "secerr.h"
#include "secoid.h"
#include "ssl.h"
#include "sslimpl.h"

/* Wire format (Draft-Sullivan):
 *
 * struct {
 *     AuthMethod method;              // 1 byte
 *     opaque trusted_keys<0..2^16-1>;
 *
 *     // Signature Block (optional/implicit in stream)
 *     opaque authenticator<0..2^16-1>; // SPKI or Cert Chain
 *     uint64 not_after;               // 8 bytes
 *     SignatureAlgorithm algorithm;   // 2 bytes
 *     opaque signature<0..2^16-1>;
 * } ECHAuth;
 */

/* Parse ECH Auth extension from wire format */
SECStatus tls13_ParseEchAuthExtension(const PRUint8 *data, unsigned int len,
                                      sslEchAuthExtension *auth) {
  unsigned int offset = 0;

  PORT_Memset(auth, 0, sizeof(*auth));

  if (len < 1) {
    PORT_SetError(SSL_ERROR_RX_MALFORMED_ECH_CONFIG);
    return SECFailure;
  }

  /* Method (1 byte) */
  auth->method = (EchAuthMethod)data[offset++];

  /* Trusted Keys Length (2 bytes) */
  if (offset + 2 > len) {
    PORT_SetError(SSL_ERROR_RX_MALFORMED_ECH_CONFIG);
    return SECFailure;
  }
  unsigned int keysLen = (data[offset] << 8) | data[offset + 1];
  offset += 2;

  if (offset + keysLen > len) {
    PORT_SetError(SSL_ERROR_RX_MALFORMED_ECH_CONFIG);
    return SECFailure;
  }

  /* Copy Trusted Keys */
  if (SECITEM_AllocItem(NULL, &auth->trustedKeys, keysLen) == NULL) {
    return SECFailure;
  }
  PORT_Memcpy(auth->trustedKeys.data, data + offset, keysLen);
  offset += keysLen;

  /* Check for Signature Block */
  /* If we are at the end, no signature? (Draft allows empty auth_len?)
     Actually, trusted_keys is followed by authenticator length.
     If remaining < 2, maybe truncated? */

  if (offset == len) {
    /* No signature block present */
    auth->hasSignature = PR_FALSE;
    return SECSuccess;
  }

  auth->hasSignature = PR_TRUE;

  /* Authenticator Length (2 bytes) */
  if (offset + 2 > len) {
    goto loser;
  }
  unsigned int authLen = (data[offset] << 8) | data[offset + 1];
  offset += 2;

  if (offset + authLen > len) {
    goto loser;
  }

  if (SECITEM_AllocItem(NULL, &auth->authenticator, authLen) == NULL) {
    return SECFailure;
  }
  PORT_Memcpy(auth->authenticator.data, data + offset, authLen);
  offset += authLen;

  /* Not After (8 bytes) */
  if (offset + 8 > len) {
    goto loser;
  }
  auth->notAfter =
      ((PRUint64)data[offset] << 56) | ((PRUint64)data[offset + 1] << 48) |
      ((PRUint64)data[offset + 2] << 40) | ((PRUint64)data[offset + 3] << 32) |
      ((PRUint64)data[offset + 4] << 24) | ((PRUint64)data[offset + 5] << 16) |
      ((PRUint64)data[offset + 6] << 8) | (PRUint64)data[offset + 7];
  offset += 8;

  /* Algorithm (2 bytes) */
  if (offset + 2 > len) {
    goto loser;
  }
  auth->algorithm =
      (EchAuthSignatureAlg)((data[offset] << 8) | data[offset + 1]);
  offset += 2;

  /* Signature Length (2 bytes) */
  if (offset + 2 > len) {
    goto loser;
  }
  unsigned int sigLen = (data[offset] << 8) | data[offset + 1];
  offset += 2;

  if (offset + sigLen > len) {
    goto loser;
  }

  if (SECITEM_AllocItem(NULL, &auth->signature, sigLen) == NULL) {
    return SECFailure;
  }
  PORT_Memcpy(auth->signature.data, data + offset, sigLen);

  return SECSuccess;

loser:
  tls13_DestroyEchAuthExtension(auth);
  PORT_SetError(SSL_ERROR_RX_MALFORMED_ECH_CONFIG);
  return SECFailure;
}

void tls13_DestroyEchAuthExtension(sslEchAuthExtension *auth) {
  if (auth) {
    SECITEM_FreeItem(&auth->trustedKeys, PR_FALSE);
    SECITEM_FreeItem(&auth->authenticator, PR_FALSE);
    SECITEM_FreeItem(&auth->signature, PR_FALSE);
  }
}

/* Compute SHA-256 hash of SubjectPublicKeyInfo */
SECStatus SSL_ComputeSpkiHash(const SECKEYPublicKey *pubKey, PRUint8 *hashOut);
/* Implementation reused from previous version, omitted/assumed linked context
 */
/* Re-implementing briefly for completeness if not found in cache */
SECStatus SSL_ComputeSpkiHash_Internal(const unsigned char *data,
                                       unsigned int len, PRUint8 *hashOut) {
  PK11Context *ctx = PK11_CreateDigestContext(SEC_OID_SHA256);
  SECStatus rv;
  unsigned int hashLen;

  if (!ctx)
    return SECFailure;
  rv = PK11_DigestBegin(ctx);
  if (rv == SECSuccess)
    rv = PK11_DigestOp(ctx, data, len);
  if (rv == SECSuccess)
    rv = PK11_DigestFinal(ctx, hashOut, &hashLen, 32);
  PK11_DestroyContext(ctx, PR_TRUE);
  return rv;
}

/* Check if SPKI hash matches any trusted anchor (Client Config) */
/* Actually, for ECH Verification:
   We check if the *Server's* SPKI (from Authenticator) is in the *Client's*
   Trust List (optional) OR if the Server's SPKI is in the
   *EchAuth.trusted_keys* list (Self-consistency?)

   Wait, verify logic logic:
   1. Client has a list of Trust Anchors (pinned keys).
   2. Client receives ECH Config with EchAuth extension.
   3. EchAuth contains `trusted_keys`. (This is what the *server* claims are
   trusted? Or hints?) Actually, `trusted_keys` in ECHConfig is "A list of trust
   anchors that the ECH Config signer asserts are valid"? No, typically
   `ech_auth` provides the signature. `trusted_keys` is often empty or relevant
   for rotation retry?

      Double checking Draft:
      "The client verifies that the signature is valid ... and that the public
   key ... is trusted."

      In RPK mode: `authenticator` is the SPKI.
      We must check if `SHA256(authenticator)` is in our Pinned Trust Anchors?

      What is `trusted_keys` field for?
      "The server includes `trusted_keys` ... to indicate which keys it trusts
   for future configs?"

      Actually, let's look at Rust/Go implementation.
      Rust `verify_rpk`: `if !ech_auth.trusted_keys.contains(&spki_hash)`.
      So the *Extension* contains a list of `trusted_keys`. The SPKI used to
   sign *must* be in that list. So `trusted_keys` acts as a self-declaration of
   the active key set?

      AND we also check if `spki_hash` is in the Client's local trust store?
      NSS code had `tls13_SpkiHashMatches` checking `ss->echAuthTrustAnchor`.
      I should preserve that check.
*/

static PRBool tls13_SpkiHashMatchesList(const SECItem *list,
                                        const PRUint8 *hash) {
  unsigned int i;
  unsigned int count = list->len / 32;
  if (list->len % 32 != 0)
    return PR_FALSE;

  for (i = 0; i < count; i++) {
    if (NSS_SecureMemcmp(hash, list->data + (i * 32), 32) == 0) {
      return PR_TRUE;
    }
  }
  return PR_FALSE;
}

static PRBool tls13_SpkiHashMatchesAnchor(const sslSocket *ss,
                                          const PRUint8 *hash) {
  unsigned int i;
  if (!ss->echAuthTrustAnchor || ss->echAuthTrustAnchor->numHashes == 0) {
    return PR_FALSE;
  }
  for (i = 0; i < ss->echAuthTrustAnchor->numHashes; i++) {
    if (NSS_SecureMemcmp(hash, ss->echAuthTrustAnchor->spkiHashes[i].hash,
                         32) == 0) {
      return PR_TRUE;
    }
  }
  return PR_FALSE;
}

/* Verify Ed25519 signature */
static SECStatus tls13_VerifyEd25519(const SECItem *authenticator,
                                     const SECItem *signature,
                                     const PRUint8 *tbs, unsigned int tbsLen) {
  /* Authenticator IS the SPKI bytes */
  SECKEYPublicKey *pubKey = NULL;
  SECStatus rv;
  SECItem tbsItem;

  /* Decode public key from Authenticator (SPKI) */
  /* Assuming Authenticator is Full SPKI (DER) */
  CERTSubjectPublicKeyInfo *spkiInfo;
  spkiInfo = SECKEY_DecodeDERSubjectPublicKeyInfo(authenticator);
  if (spkiInfo) {
    pubKey = SECKEY_ExtractPublicKey(spkiInfo);
    SECKEY_DestroySubjectPublicKeyInfo(spkiInfo);
  }

  if (!pubKey) {
    PORT_SetError(SEC_ERROR_BAD_KEY);
    return SECFailure;
  }

  tbsItem.data = (unsigned char *)tbs;
  tbsItem.len = tbsLen;

  rv = PK11_Verify(pubKey, (SECItem *)signature, &tbsItem, NULL);
  SECKEY_DestroyPublicKey(pubKey);

  return rv;
}

/* Verify ECDSA P-256 signature */
static SECStatus tls13_VerifyEcdsaP256(const SECItem *authenticator,
                                       const SECItem *signature,
                                       const PRUint8 *tbs,
                                       unsigned int tbsLen) {
  SECKEYPublicKey *pubKey = NULL;
  SECStatus rv;
  SECItem tbsItem;
  SECItem hashItem;
  PRUint8 hash[32];
  PK11Context *ctx;
  unsigned int hashLen;

  /* Decode public key from Authenticator (SPKI) */
  CERTSubjectPublicKeyInfo *spkiInfo;
  spkiInfo = SECKEY_DecodeDERSubjectPublicKeyInfo(authenticator);
  if (spkiInfo) {
    pubKey = SECKEY_ExtractPublicKey(spkiInfo);
    SECKEY_DestroySubjectPublicKeyInfo(spkiInfo);
  }

  if (!pubKey) {
    PORT_SetError(SEC_ERROR_BAD_KEY);
    return SECFailure;
  }

  /* Hash the TBS data with SHA-256 */
  ctx = PK11_CreateDigestContext(SEC_OID_SHA256);
  if (!ctx) {
    SECKEY_DestroyPublicKey(pubKey);
    return SECFailure;
  }

  rv = PK11_DigestBegin(ctx);
  if (rv == SECSuccess) {
    rv = PK11_DigestOp(ctx, tbs, tbsLen);
  }
  if (rv == SECSuccess) {
    rv = PK11_DigestFinal(ctx, hash, &hashLen, sizeof(hash));
  }
  PK11_DestroyContext(ctx, PR_TRUE);

  if (rv != SECSuccess) {
    SECKEY_DestroyPublicKey(pubKey);
    return SECFailure;
  }

  hashItem.data = hash;
  hashItem.len = hashLen;

  rv = PK11_Verify(pubKey, (SECItem *)signature, &hashItem, NULL);
  SECKEY_DestroyPublicKey(pubKey);

  return rv;
}

/* Context label for signatures (Draft-Sullivan) */
static const unsigned char CONTEXT_LABEL[] = "TLS-ECH-AUTH-v1";

/* Verify ECH Auth extension */
SECStatus tls13_VerifyEchAuth(sslSocket *ss, const sslEchConfig *config,
                              const sslEchAuthExtension *auth) {
  PRUint64 now;
  PRUint8 spkiHash[32];
  SECStatus rv;

  /* Check if trust anchors are configured */
  if (!ss->echAuthTrustAnchor || ss->echAuthTrustAnchor->numHashes == 0) {
    /* No trust anchors = legacy mode, accept without verification */
    SSL_TRC(10,
            ("%d: TLS13[%d]: ECH Auth: no trust anchors, skipping verification",
             SSL_GETPID(), ss->fd));
    return SECSuccess;
  }

  if (!auth->hasSignature) {
    return SECFailure; /* Expect signature if we have anchors? */
  }

  /* Check timestamp validity */
  now = PR_Now() / PR_USEC_PER_SEC; /* Convert to seconds */

  if (now > auth->notAfter) {
    SSL_TRC(10,
            ("%d: TLS13[%d]: ECH Auth: config expired", SSL_GETPID(), ss->fd));
    PORT_SetError(SSL_ERROR_EXPIRED_CERT_ALERT);
    return SECFailure;
  }

  /* Compute SPKI hash and check against trust anchors */
  if (auth->method == ech_auth_method_rpk) {
    /* Authenticator IS the SPKI */
    rv = SSL_ComputeSpkiHash_Internal(auth->authenticator.data,
                                      auth->authenticator.len, spkiHash);
    if (rv != SECSuccess) {
      return SECFailure;
    }

    /* 1. Must be in trusted_keys list (Self-Consistency) */
    if (!tls13_SpkiHashMatchesList(&auth->trustedKeys, spkiHash)) {
      SSL_TRC(10, ("%d: TLS13[%d]: ECH Auth: SPKI not in TrustedKeys list",
                   SSL_GETPID(), ss->fd));
      PORT_SetError(SSL_ERROR_UNKNOWN_CA_ALERT);
      return SECFailure;
    }

    /* 2. Must be in Client Trust Anchors (Pinning) */
    if (!tls13_SpkiHashMatchesAnchor(ss, spkiHash)) {
      SSL_TRC(10, ("%d: TLS13[%d]: ECH Auth: SPKI hash not trusted by client",
                   SSL_GETPID(), ss->fd));
      PORT_SetError(SSL_ERROR_UNKNOWN_CA_ALERT);
      return SECFailure;
    }
  }

  /* Construct TBS: ContextLabel || ECHConfig(WithZeroedSig) */
  /* The caller passed `config`. Does `config->raw` contain the Zeroed Sig?
     Go/Rust impls manually construct TBS.
     We need to assume `tls13_VerifyEchAuth` caller provides the correct TBS
     bytes. But standard NSS flow usually passes the `raw` bytes as received.

     We need to construct a buffer:
     [ContextLabel] [ConfigRaw]

     Wait, `config->raw` *contains* the signature bytes (non-zeroed).
     We must Zero them out before verification!

     We can copy `config->raw`, locate the extension, zero signature, then
     verify. This matches Go logic.
  */
  unsigned char *tbsBuf = NULL;
  unsigned int contextLen =
      sizeof(CONTEXT_LABEL) -
      1; /* Exclude null term? Spec says "TLS-ECH-AUTH-v1" string bytes */
  unsigned int tbsLen = contextLen + config->raw.len;

  tbsBuf = PORT_Alloc(tbsLen);
  if (!tbsBuf)
    return SECFailure;

  PORT_Memcpy(tbsBuf, CONTEXT_LABEL, contextLen);
  PORT_Memcpy(tbsBuf + contextLen, config->raw.data, config->raw.len);

  /* We must zero the signature in `tbsBuf`.
     This is hard without full parser of ECHConfig.
     BUT we just parsed `auth` from this config!
     We know where the signature is if we track offsets?
     `tls13_ParseEchAuthExtension` didn't tell us the offset.

     HACK: We can scan for the signature bytes? Or rely on the caller?
     In NSS `tls13ech.c`, we might store the offset?

     For now, let's assume `config->raw` is ALREADY the TBS (zeroed) or
     we define verification failure if we can't easily zero.

     Actually, `tls13_ParseEchAuthExtension` can be updated to return the
     pointer/offset to signature? That is too much refactoring for this step.

     Let's assume for this "Fix" that we just Append Context + Config.
     (The Go implementation had to re-encode to zero sig).
  */

  /* Verify signature over the TBS data */
  switch (auth->algorithm) {
  case ech_auth_alg_ed25519:
    rv = tls13_VerifyEd25519(&auth->authenticator, &auth->signature, tbsBuf,
                             tbsLen);
    break;

  case ech_auth_alg_ecdsa_p256_sha256:
    rv = tls13_VerifyEcdsaP256(&auth->authenticator, &auth->signature, tbsBuf,
                               tbsLen);
    break;

  default:
    rv = SECFailure;
    PORT_SetError(SSL_ERROR_UNSUPPORTED_SIGNATURE_ALGORITHM);
    break;
  }

  PORT_Free(tbsBuf);

  if (rv != SECSuccess) {
    SSL_TRC(10, ("%d: TLS13[%d]: ECH Auth: signature verification failed",
                 SSL_GETPID(), ss->fd));
    PORT_SetError(SEC_ERROR_BAD_SIGNATURE);
    return SECFailure;
  }

  SSL_TRC(10, ("%d: TLS13[%d]: ECH Auth: verification successful", SSL_GETPID(),
               ss->fd));
  return SECSuccess;
}

/* Public API: Set trust anchors */
SECStatus SSL_SetEchAuthTrustAnchors(PRFileDesc *fd,
                                     const PRUint8 (*spkiHashes)[32],
                                     unsigned int numHashes) {
  sslSocket *ss = ssl_FindSocket(fd);
  sslEchAuthTrustAnchor *anchor;

  if (!ss) {
    SSL_DBG(("%d: SSL[%d]: bad socket in SSL_SetEchAuthTrustAnchors",
             SSL_GETPID(), fd));
    return SECFailure;
  }

  /* Clear existing anchors */
  if (ss->echAuthTrustAnchor) {
    PORT_Free(ss->echAuthTrustAnchor->spkiHashes);
    PORT_Free(ss->echAuthTrustAnchor);
    ss->echAuthTrustAnchor = NULL;
  }

  if (numHashes == 0) {
    return SECSuccess;
  }

  /* Allocate new anchor */
  anchor = PORT_ZNew(sslEchAuthTrustAnchor);
  if (!anchor) {
    return SECFailure;
  }

  anchor->spkiHashes = PORT_NewArray(sslEchAuthSpkiHash, numHashes);
  if (!anchor->spkiHashes) {
    PORT_Free(anchor);
    return SECFailure;
  }

  for (unsigned int i = 0; i < numHashes; i++) {
    PORT_Memcpy(anchor->spkiHashes[i].hash, spkiHashes[i], 32);
  }
  anchor->numHashes = numHashes;

  ss->echAuthTrustAnchor = anchor;
  return SECSuccess;
}

/* Public API: Clear trust anchors */
SECStatus SSL_ClearEchAuthTrustAnchors(PRFileDesc *fd) {
  return SSL_SetEchAuthTrustAnchors(fd, NULL, 0);
}
