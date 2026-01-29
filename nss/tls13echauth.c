/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * ECH Auth Extension Implementation (draft-sullivan-tls-signed-ech-updates)
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include "ssl.h"
#include "sslimpl.h"
#include "tls13echauth.h"
#include "pk11pub.h"
#include "secder.h"
#include "keyhi.h"
#include "secoid.h"
#include "secerr.h"

/* Wire format:
 *
 * struct {
 *     AuthMethod method;              // 1 byte
 *     uint64 not_before;              // 8 bytes
 *     uint64 not_after;               // 8 bytes
 *     SignatureAlgorithm algorithm;   // 2 bytes
 *     opaque spki<0..2^16-1>;         // Public key or cert chain
 *     opaque signature<0..2^16-1>;
 * } ECHAuthExtension;
 */

/* Parse ECH Auth extension from wire format */
SECStatus
tls13_ParseEchAuthExtension(const PRUint8 *data, unsigned int len,
                            sslEchAuthExtension *auth)
{
    unsigned int offset = 0;

    PORT_Memset(auth, 0, sizeof(*auth));

    /* Minimum size: 1 + 8 + 8 + 2 + 2 + 2 = 23 bytes */
    if (len < 23) {
        PORT_SetError(SSL_ERROR_RX_MALFORMED_ECH_CONFIG);
        return SECFailure;
    }

    /* Method (1 byte) */
    auth->method = (EchAuthMethod)data[offset++];
    if (auth->method != ech_auth_method_rpk &&
        auth->method != ech_auth_method_pkix) {
        PORT_SetError(SSL_ERROR_UNSUPPORTED_SIGNATURE_ALGORITHM);
        return SECFailure;
    }

    /* not_before (8 bytes, big-endian) */
    auth->notBefore = ((PRUint64)data[offset] << 56) |
                      ((PRUint64)data[offset + 1] << 48) |
                      ((PRUint64)data[offset + 2] << 40) |
                      ((PRUint64)data[offset + 3] << 32) |
                      ((PRUint64)data[offset + 4] << 24) |
                      ((PRUint64)data[offset + 5] << 16) |
                      ((PRUint64)data[offset + 6] << 8) |
                      (PRUint64)data[offset + 7];
    offset += 8;

    /* not_after (8 bytes, big-endian) */
    auth->notAfter = ((PRUint64)data[offset] << 56) |
                     ((PRUint64)data[offset + 1] << 48) |
                     ((PRUint64)data[offset + 2] << 40) |
                     ((PRUint64)data[offset + 3] << 32) |
                     ((PRUint64)data[offset + 4] << 24) |
                     ((PRUint64)data[offset + 5] << 16) |
                     ((PRUint64)data[offset + 6] << 8) |
                     (PRUint64)data[offset + 7];
    offset += 8;

    /* Algorithm (2 bytes) */
    auth->algorithm = (EchAuthSignatureAlg)((data[offset] << 8) | data[offset + 1]);
    offset += 2;

    /* SPKI length (2 bytes) */
    if (offset + 2 > len) {
        PORT_SetError(SSL_ERROR_RX_MALFORMED_ECH_CONFIG);
        return SECFailure;
    }
    unsigned int spkiLen = (data[offset] << 8) | data[offset + 1];
    offset += 2;

    if (offset + spkiLen > len) {
        PORT_SetError(SSL_ERROR_RX_MALFORMED_ECH_CONFIG);
        return SECFailure;
    }

    /* Copy SPKI */
    if (SECITEM_AllocItem(NULL, &auth->spki, spkiLen) == NULL) {
        return SECFailure;
    }
    PORT_Memcpy(auth->spki.data, data + offset, spkiLen);
    offset += spkiLen;

    /* Signature length (2 bytes) */
    if (offset + 2 > len) {
        SECITEM_FreeItem(&auth->spki, PR_FALSE);
        PORT_SetError(SSL_ERROR_RX_MALFORMED_ECH_CONFIG);
        return SECFailure;
    }
    unsigned int sigLen = (data[offset] << 8) | data[offset + 1];
    offset += 2;

    if (offset + sigLen > len) {
        SECITEM_FreeItem(&auth->spki, PR_FALSE);
        PORT_SetError(SSL_ERROR_RX_MALFORMED_ECH_CONFIG);
        return SECFailure;
    }

    /* Copy signature */
    if (SECITEM_AllocItem(NULL, &auth->signature, sigLen) == NULL) {
        SECITEM_FreeItem(&auth->spki, PR_FALSE);
        return SECFailure;
    }
    PORT_Memcpy(auth->signature.data, data + offset, sigLen);

    return SECSuccess;
}

void
tls13_DestroyEchAuthExtension(sslEchAuthExtension *auth)
{
    if (auth) {
        SECITEM_FreeItem(&auth->spki, PR_FALSE);
        SECITEM_FreeItem(&auth->signature, PR_FALSE);
    }
}

/* Compute SHA-256 hash of SubjectPublicKeyInfo */
SECStatus
SSL_ComputeSpkiHash(const SECKEYPublicKey *pubKey, PRUint8 *hashOut)
{
    SECItem *spkiDer = NULL;
    SECStatus rv;
    PK11Context *ctx = NULL;
    unsigned int hashLen;

    /* Encode public key as SubjectPublicKeyInfo */
    spkiDer = SECKEY_EncodeDERSubjectPublicKeyInfo(pubKey);
    if (!spkiDer) {
        return SECFailure;
    }

    /* Compute SHA-256 */
    ctx = PK11_CreateDigestContext(SEC_OID_SHA256);
    if (!ctx) {
        SECITEM_FreeItem(spkiDer, PR_TRUE);
        return SECFailure;
    }

    rv = PK11_DigestBegin(ctx);
    if (rv != SECSuccess) {
        goto loser;
    }

    rv = PK11_DigestOp(ctx, spkiDer->data, spkiDer->len);
    if (rv != SECSuccess) {
        goto loser;
    }

    rv = PK11_DigestFinal(ctx, hashOut, &hashLen, 32);
    if (rv != SECSuccess || hashLen != 32) {
        goto loser;
    }

    PK11_DestroyContext(ctx, PR_TRUE);
    SECITEM_FreeItem(spkiDer, PR_TRUE);
    return SECSuccess;

loser:
    if (ctx) {
        PK11_DestroyContext(ctx, PR_TRUE);
    }
    SECITEM_FreeItem(spkiDer, PR_TRUE);
    return SECFailure;
}

/* Check if SPKI hash matches any trusted anchor */
static PRBool
tls13_SpkiHashMatches(const sslSocket *ss, const PRUint8 *hash)
{
    unsigned int i;

    if (!ss->echAuthTrustAnchor || ss->echAuthTrustAnchor->numHashes == 0) {
        return PR_FALSE;
    }

    for (i = 0; i < ss->echAuthTrustAnchor->numHashes; i++) {
        if (NSS_SecureMemcmp(hash, ss->echAuthTrustAnchor->spkiHashes[i].hash, 32) == 0) {
            return PR_TRUE;
        }
    }

    return PR_FALSE;
}

/* Verify Ed25519 signature */
static SECStatus
tls13_VerifyEd25519(const SECItem *spki, const SECItem *signature,
                    const PRUint8 *tbs, unsigned int tbsLen)
{
    SECKEYPublicKey *pubKey = NULL;
    SECStatus rv;
    SECItem tbsItem;

    /* Decode public key from SPKI */
    pubKey = SECKEY_ExtractPublicKey(
        &(SECKEYSubjectPublicKeyInfo){
            .algorithm = { SEC_OID_ED25519 },
            .subjectPublicKey = *spki
        });

    if (!pubKey) {
        /* Try decoding as raw DER */
        CERTSubjectPublicKeyInfo *spkiInfo;
        spkiInfo = SECKEY_DecodeDERSubjectPublicKeyInfo(spki);
        if (spkiInfo) {
            pubKey = SECKEY_ExtractPublicKey(spkiInfo);
            SECKEY_DestroySubjectPublicKeyInfo(spkiInfo);
        }
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
static SECStatus
tls13_VerifyEcdsaP256(const SECItem *spki, const SECItem *signature,
                      const PRUint8 *tbs, unsigned int tbsLen)
{
    SECKEYPublicKey *pubKey = NULL;
    SECStatus rv;
    SECItem tbsItem;
    SECItem hashItem;
    PRUint8 hash[32];
    PK11Context *ctx;
    unsigned int hashLen;

    /* Decode public key from SPKI */
    CERTSubjectPublicKeyInfo *spkiInfo;
    spkiInfo = SECKEY_DecodeDERSubjectPublicKeyInfo(spki);
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

/* Verify ECH Auth extension */
SECStatus
tls13_VerifyEchAuth(sslSocket *ss, const sslEchConfig *config,
                    const sslEchAuthExtension *auth)
{
    PRUint64 now;
    PRUint8 spkiHash[32];
    SECStatus rv;

    /* Check if trust anchors are configured */
    if (!ss->echAuthTrustAnchor || ss->echAuthTrustAnchor->numHashes == 0) {
        /* No trust anchors = legacy mode, accept without verification */
        SSL_TRC(10, ("%d: TLS13[%d]: ECH Auth: no trust anchors, skipping verification",
                     SSL_GETPID(), ss->fd));
        return SECSuccess;
    }

    /* Check timestamp validity */
    now = PR_Now() / PR_USEC_PER_SEC; /* Convert to seconds */

    if (now < auth->notBefore) {
        SSL_TRC(10, ("%d: TLS13[%d]: ECH Auth: config not yet valid",
                     SSL_GETPID(), ss->fd));
        PORT_SetError(SSL_ERROR_EXPIRED_CERT_ALERT);
        return SECFailure;
    }

    if (now > auth->notAfter) {
        SSL_TRC(10, ("%d: TLS13[%d]: ECH Auth: config expired",
                     SSL_GETPID(), ss->fd));
        PORT_SetError(SSL_ERROR_EXPIRED_CERT_ALERT);
        return SECFailure;
    }

    /* Compute SPKI hash and check against trust anchors */
    if (auth->method == ech_auth_method_rpk) {
        /* For RPK, hash the SPKI directly */
        PK11Context *ctx = PK11_CreateDigestContext(SEC_OID_SHA256);
        unsigned int hashLen;

        if (!ctx) {
            return SECFailure;
        }

        rv = PK11_DigestBegin(ctx);
        if (rv == SECSuccess) {
            rv = PK11_DigestOp(ctx, auth->spki.data, auth->spki.len);
        }
        if (rv == SECSuccess) {
            rv = PK11_DigestFinal(ctx, spkiHash, &hashLen, sizeof(spkiHash));
        }
        PK11_DestroyContext(ctx, PR_TRUE);

        if (rv != SECSuccess) {
            return SECFailure;
        }

        if (!tls13_SpkiHashMatches(ss, spkiHash)) {
            SSL_TRC(10, ("%d: TLS13[%d]: ECH Auth: SPKI hash not trusted",
                         SSL_GETPID(), ss->fd));
            PORT_SetError(SSL_ERROR_UNKNOWN_CA_ALERT);
            return SECFailure;
        }
    }

    /* Verify signature over the ECHConfig (with signature zeroed) */
    /* The TBS is the raw ECHConfig bytes */
    switch (auth->algorithm) {
        case ech_auth_alg_ed25519:
            rv = tls13_VerifyEd25519(&auth->spki, &auth->signature,
                                     config->raw.data, config->raw.len);
            break;

        case ech_auth_alg_ecdsa_p256_sha256:
            rv = tls13_VerifyEcdsaP256(&auth->spki, &auth->signature,
                                       config->raw.data, config->raw.len);
            break;

        default:
            SSL_TRC(10, ("%d: TLS13[%d]: ECH Auth: unsupported algorithm 0x%04x",
                         SSL_GETPID(), ss->fd, auth->algorithm));
            PORT_SetError(SSL_ERROR_UNSUPPORTED_SIGNATURE_ALGORITHM);
            return SECFailure;
    }

    if (rv != SECSuccess) {
        SSL_TRC(10, ("%d: TLS13[%d]: ECH Auth: signature verification failed",
                     SSL_GETPID(), ss->fd));
        PORT_SetError(SEC_ERROR_BAD_SIGNATURE);
        return SECFailure;
    }

    SSL_TRC(10, ("%d: TLS13[%d]: ECH Auth: verification successful",
                 SSL_GETPID(), ss->fd));
    return SECSuccess;
}

/* Public API: Set trust anchors */
SECStatus
SSL_SetEchAuthTrustAnchors(PRFileDesc *fd, const PRUint8 (*spkiHashes)[32],
                           unsigned int numHashes)
{
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
SECStatus
SSL_ClearEchAuthTrustAnchors(PRFileDesc *fd)
{
    return SSL_SetEchAuthTrustAnchors(fd, NULL, 0);
}
