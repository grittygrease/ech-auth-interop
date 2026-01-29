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

#include "seccomon.h"
#include "secitem.h"
#include "pk11pub.h"

/* ECH Auth extension type (TBD - using private use for now) */
#define TLS13_ECH_AUTH_EXTENSION_TYPE 0xff01

/* Authentication methods */
typedef enum {
    ech_auth_method_none = 0,
    ech_auth_method_rpk = 1,   /* Raw Public Key with SPKI pinning */
    ech_auth_method_pkix = 2   /* X.509 certificate chain */
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
    PRUint64 notBefore;
    PRUint64 notAfter;
    EchAuthSignatureAlg algorithm;
    SECItem spki;        /* Public key (RPK) or certificate chain (PKIX) */
    SECItem signature;
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
SECStatus SSL_ComputeSpkiHash(const SECKEYPublicKey *pubKey,
                              PRUint8 *hashOut);

SEC_END_PROTOS

/* Internal functions */
SECStatus tls13_ParseEchAuthExtension(const PRUint8 *data, unsigned int len,
                                      sslEchAuthExtension *auth);
SECStatus tls13_VerifyEchAuth(sslSocket *ss, const sslEchConfig *config,
                              const sslEchAuthExtension *auth);
void tls13_DestroyEchAuthExtension(sslEchAuthExtension *auth);

#endif /* __tls13echauth_h_ */
