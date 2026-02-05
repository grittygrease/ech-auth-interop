/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * ECH Auth Extension Support (draft-sullivan-tls-signed-ech-updates)
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef __tls13echauth_h_
#define __tls13echauth_h_

#include "keythi.h"
#include "pk11pub.h"
#include "prtypes.h"
#include "seccomon.h"
#include "secitem.h"

/* ECH Auth extension type (draft-sullivan-tls-signed-ech-updates) */
#define TLS13_ECH_AUTH_EXTENSION_TYPE 0xfe0d

/* Authentication methods (Draft-Sullivan PR#2) */
typedef enum {
  ech_auth_method_rpk = 0, /* Raw Public Key with SPKI pinning */
  ech_auth_method_pkix = 1 /* X.509 certificate chain */
} EchAuthMethod;

/* Signature algorithms */
typedef enum {
  ech_auth_alg_ed25519 = 0x0807,
  ech_auth_alg_ecdsa_p256_sha256 = 0x0403
} EchAuthSignatureAlg;

/* SPKI hash for trust anchor pinning */
typedef struct sslEchAuthSpkiHashStr {
  PRUint8 hash[32]; /* SHA-256 */
} sslEchAuthSpkiHash;

/* Trust anchor configuration */
typedef struct sslEchAuthTrustAnchorStr {
  sslEchAuthSpkiHash *spkiHashes;
  unsigned int numHashes;
} sslEchAuthTrustAnchor;

/* Parsed ECH Auth extension */
typedef struct sslEchAuthExtensionStr {
  EchAuthMethod method;

  /* Trusted Keys (wire: trusted_keys<0..2^16-1>) */
  SECItem trustedKeys; /* List of 32-byte hashes */

  /* Signature Block Fields */
  PRBool hasSignature;
  SECItem authenticator; /* Wire: authenticator<0..2^16-1> */
  PRUint64 notAfter;
  EchAuthSignatureAlg algorithm;
  SECItem signature; /* Wire: signature<0..2^16-1> */
} sslEchAuthExtension;

/* Extended ECHConfig with auth extension */
typedef struct sslEchConfigAuthStr {
  PRBool hasAuth;
  sslEchAuthExtension auth;
} sslEchConfigAuth;

SEC_BEGIN_PROTOS

/*
 * Set trust anchors for ECH Auth verification.
 * The client will only accept retry configs signed by keys matching
 * one of the provided SPKI hashes.
 *
 * fd: SSL socket
 * spkiHashes: Array of SHA-256 SPKI hashes
 * numHashes: Number of hashes in the array
 *
 * If numHashes is 0, ECH Auth verification is disabled (legacy mode).
 * Returns SECSuccess on success, SECFailure on error.
 */
SECStatus SSL_SetEchAuthTrustAnchors(PRFileDesc *fd,
                                     const PRUint8 (*spkiHashes)[32],
                                     unsigned int numHashes);

/*
 * Clear ECH Auth trust anchors.
 */
SECStatus SSL_ClearEchAuthTrustAnchors(PRFileDesc *fd);

/*
 * Get the SPKI hash of a public key.
 * Computes SHA-256(SubjectPublicKeyInfo).
 */
SECStatus SSL_ComputeSpkiHash(const SECKEYPublicKey *pubKey, PRUint8 *hashOut);

/*
 * Sign an ECH config using the specified method and key.
 *
 * configOriginal: The unsigned ECHConfig (binary)
 * method: ech_auth_method_rpk or ech_auth_method_pkix
 * privKey: Private key for signing
 * authenticator: SPKI (for RPK) or Cert Chain (for PKIX)
 * algorithm: Signature algorithm (Ed25519 or P-256)
 * notAfter: Expiration timestamp (MUST be 0 for PKIX)
 * signedConfigOut: Buffer to receive the full signed ECHConfig (caller must
 * free)
 *
 * COMPLIANCE NOTE: For PKIX method, notAfter MUST be 0. Certificate validity
 * governs expiration. Function returns SECFailure if notAfter != 0 for PKIX.
 */
SECStatus SSL_SignEchConfig(const SECItem *configOriginal, EchAuthMethod method,
                            SECKEYPrivateKey *privKey,
                            const SECItem *authenticator,
                            EchAuthSignatureAlg algorithm, PRUint64 notAfter,
                            SECItem *signedConfigOut);

SEC_END_PROTOS

#endif /* __tls13echauth_h_ */
