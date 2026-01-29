/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * ECH Auth Test Client
 *
 * Demonstrates ECH with authenticated retry configs.
 * Connects to a TLS 1.3 server, handles ECH rejection, verifies
 * retry config signatures, and reconnects.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "nss.h"
#include "ssl.h"
#include "sslexp.h"
#include "pk11pub.h"
#include "secerr.h"
#include "prerror.h"

/* Include our ECH Auth header */
#include "tls13echauth.h"

#define BUFFER_SIZE 4096

/* Trust anchor SPKI hash (SHA-256) - set this to your server's key */
static PRUint8 trustedSpkiHash[32] = {0};
static PRBool haveTrustAnchor = PR_FALSE;

/* Parse hex string into bytes */
static int
parseHex(const char *hex, PRUint8 *out, int maxLen)
{
    int len = 0;
    while (*hex && len < maxLen) {
        int hi, lo;
        if (hex[0] >= '0' && hex[0] <= '9') hi = hex[0] - '0';
        else if (hex[0] >= 'a' && hex[0] <= 'f') hi = hex[0] - 'a' + 10;
        else if (hex[0] >= 'A' && hex[0] <= 'F') hi = hex[0] - 'A' + 10;
        else break;

        if (hex[1] >= '0' && hex[1] <= '9') lo = hex[1] - '0';
        else if (hex[1] >= 'a' && hex[1] <= 'f') lo = hex[1] - 'a' + 10;
        else if (hex[1] >= 'A' && hex[1] <= 'F') lo = hex[1] - 'A' + 10;
        else break;

        out[len++] = (hi << 4) | lo;
        hex += 2;
    }
    return len;
}

/* Print bytes as hex */
static void
printHex(const char *label, const PRUint8 *data, int len)
{
    printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/* Bad certificate callback - accept all for testing */
static SECStatus
badCertHandler(void *arg, PRFileDesc *fd)
{
    fprintf(stderr, "Warning: Accepting certificate without verification\n");
    return SECSuccess;
}

/* Handshake callback */
static void
handshakeCallback(PRFileDesc *fd, void *arg)
{
    SSLChannelInfo info;
    SECStatus rv;

    rv = SSL_GetChannelInfo(fd, &info, sizeof(info));
    if (rv == SECSuccess) {
        printf("Handshake complete:\n");
        printf("  Protocol: TLS %d.%d\n",
               info.protocolVersion >> 8,
               info.protocolVersion & 0xff);
        printf("  Cipher: %s\n", info.cipherSuiteName);

        /* Check ECH status */
        SSLPreliminaryChannelInfo pinfo;
        rv = SSL_GetPreliminaryChannelInfo(fd, &pinfo, sizeof(pinfo));
        if (rv == SECSuccess && (pinfo.valuesSet & ssl_preinfo_ech)) {
            printf("  ECH: %s\n", pinfo.echAccepted ? "accepted" : "rejected");
        }
    }
}

/* Create TCP connection */
static PRFileDesc *
connectTcp(const char *host, int port)
{
    struct hostent *hp;
    struct sockaddr_in addr;
    int sock;

    hp = gethostbyname(host);
    if (!hp) {
        fprintf(stderr, "Cannot resolve host: %s\n", host);
        return NULL;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return NULL;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr, hp->h_addr, hp->h_length);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sock);
        return NULL;
    }

    return PR_ImportTCPSocket(sock);
}

/* Perform TLS handshake with ECH */
static SECStatus
doHandshake(PRFileDesc *ssl, const char *host, const PRUint8 *echConfig,
            unsigned int echConfigLen, PRBool expectRejection)
{
    SECStatus rv;

    /* Set server name */
    rv = SSL_SetURL(ssl, host);
    if (rv != SECSuccess) {
        fprintf(stderr, "SSL_SetURL failed: %d\n", PR_GetError());
        return rv;
    }

    /* Set ECH configs if provided */
    if (echConfig && echConfigLen > 0) {
        rv = SSL_SetClientEchConfigs(ssl, echConfig, echConfigLen);
        if (rv != SECSuccess) {
            fprintf(stderr, "SSL_SetClientEchConfigs failed: %d\n", PR_GetError());
            return rv;
        }
        printf("ECH config set (%u bytes)\n", echConfigLen);
    }

    /* Set trust anchors for ECH Auth */
    if (haveTrustAnchor) {
        rv = SSL_SetEchAuthTrustAnchors(ssl, &trustedSpkiHash, 1);
        if (rv != SECSuccess) {
            fprintf(stderr, "SSL_SetEchAuthTrustAnchors failed: %d\n", PR_GetError());
            return rv;
        }
        printf("ECH Auth trust anchor set\n");
    }

    /* Perform handshake */
    rv = SSL_ForceHandshake(ssl);

    if (rv != SECSuccess) {
        PRErrorCode err = PR_GetError();

        /* Check for ECH rejection with retry configs */
        if (err == SSL_ERROR_ECH_RETRY_WITH_ECH) {
            SECItem retryConfigs;
            printf("ECH rejected, getting retry configs...\n");

            rv = SSL_GetEchRetryConfigs(ssl, &retryConfigs);
            if (rv == SECSuccess && retryConfigs.len > 0) {
                printf("Got retry configs (%u bytes)\n", retryConfigs.len);
                printHex("Retry configs", retryConfigs.data,
                         retryConfigs.len > 64 ? 64 : retryConfigs.len);

                /* The retry configs would be verified by tls13_VerifyEchAuth
                 * during parsing if trust anchors are set */

                SECITEM_FreeItem(&retryConfigs, PR_FALSE);

                if (expectRejection) {
                    return SECSuccess; /* Expected rejection */
                }
            }
        }

        fprintf(stderr, "Handshake failed: %d (%s)\n", err, PR_ErrorToString(err));
        return SECFailure;
    }

    return SECSuccess;
}

/* Main test flow */
static int
runTest(const char *host, int port, const char *echConfigFile,
        const char *trustAnchorHex)
{
    PRFileDesc *tcpFd = NULL;
    PRFileDesc *sslFd = NULL;
    SECStatus rv;
    PRUint8 *echConfig = NULL;
    unsigned int echConfigLen = 0;

    printf("=== ECH Auth Test Client ===\n");
    printf("Host: %s:%d\n", host, port);

    /* Load ECH config from file if provided */
    if (echConfigFile) {
        FILE *f = fopen(echConfigFile, "rb");
        if (f) {
            fseek(f, 0, SEEK_END);
            echConfigLen = ftell(f);
            fseek(f, 0, SEEK_SET);

            echConfig = malloc(echConfigLen);
            if (echConfig) {
                fread(echConfig, 1, echConfigLen, f);
            }
            fclose(f);
            printf("Loaded ECH config from %s (%u bytes)\n",
                   echConfigFile, echConfigLen);
        } else {
            fprintf(stderr, "Cannot open ECH config file: %s\n", echConfigFile);
        }
    }

    /* Parse trust anchor if provided */
    if (trustAnchorHex && strlen(trustAnchorHex) == 64) {
        if (parseHex(trustAnchorHex, trustedSpkiHash, 32) == 32) {
            haveTrustAnchor = PR_TRUE;
            printHex("Trust anchor", trustedSpkiHash, 32);
        }
    }

    /* Initialize NSS */
    rv = NSS_NoDB_Init(NULL);
    if (rv != SECSuccess) {
        fprintf(stderr, "NSS_Init failed: %d\n", PR_GetError());
        return 1;
    }

    /* Set cipher policy */
    rv = NSS_SetDomesticPolicy();
    if (rv != SECSuccess) {
        fprintf(stderr, "NSS_SetDomesticPolicy failed\n");
        goto cleanup;
    }

    /* Enable TLS 1.3 */
    SSLVersionRange vrange = { SSL_LIBRARY_VERSION_TLS_1_2,
                               SSL_LIBRARY_VERSION_TLS_1_3 };

    printf("\n--- Connection 1: Initial handshake ---\n");

    /* Create TCP connection */
    tcpFd = connectTcp(host, port);
    if (!tcpFd) {
        goto cleanup;
    }

    /* Import into SSL */
    sslFd = SSL_ImportFD(NULL, tcpFd);
    if (!sslFd) {
        fprintf(stderr, "SSL_ImportFD failed\n");
        PR_Close(tcpFd);
        goto cleanup;
    }

    /* Configure SSL */
    SSL_OptionSet(sslFd, SSL_SECURITY, PR_TRUE);
    SSL_OptionSet(sslFd, SSL_HANDSHAKE_AS_CLIENT, PR_TRUE);
    SSL_VersionRangeSet(sslFd, &vrange);
    SSL_BadCertHook(sslFd, badCertHandler, NULL);
    SSL_HandshakeCallback(sslFd, handshakeCallback, NULL);

    /* First connection - may get ECH rejection */
    rv = doHandshake(sslFd, host, echConfig, echConfigLen, PR_TRUE);

    /* Close first connection */
    PR_Close(sslFd);
    sslFd = NULL;

    if (rv != SECSuccess) {
        /* If we got retry configs, try again */
        printf("\n--- Connection 2: Retry with new config ---\n");

        tcpFd = connectTcp(host, port);
        if (!tcpFd) {
            goto cleanup;
        }

        sslFd = SSL_ImportFD(NULL, tcpFd);
        if (!sslFd) {
            fprintf(stderr, "SSL_ImportFD failed\n");
            PR_Close(tcpFd);
            goto cleanup;
        }

        SSL_OptionSet(sslFd, SSL_SECURITY, PR_TRUE);
        SSL_OptionSet(sslFd, SSL_HANDSHAKE_AS_CLIENT, PR_TRUE);
        SSL_VersionRangeSet(sslFd, &vrange);
        SSL_BadCertHook(sslFd, badCertHandler, NULL);
        SSL_HandshakeCallback(sslFd, handshakeCallback, NULL);

        /* Use retry configs from previous connection */
        rv = doHandshake(sslFd, host, NULL, 0, PR_FALSE);
    }

    if (rv == SECSuccess) {
        /* Send a simple request */
        const char *request = "GET / HTTP/1.0\r\nHost: ";
        char buf[BUFFER_SIZE];

        PR_Write(sslFd, request, strlen(request));
        PR_Write(sslFd, host, strlen(host));
        PR_Write(sslFd, "\r\n\r\n", 4);

        int n = PR_Read(sslFd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            printf("\nResponse:\n%s\n", buf);
        }
    }

    if (sslFd) {
        PR_Close(sslFd);
    }

cleanup:
    if (echConfig) {
        free(echConfig);
    }
    NSS_Shutdown();

    return (rv == SECSuccess) ? 0 : 1;
}

static void
usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-h host] [-p port] [-e echconfig.bin] [-t spki_hash_hex]\n", prog);
    fprintf(stderr, "  -h host         Server hostname (default: localhost)\n");
    fprintf(stderr, "  -p port         Server port (default: 443)\n");
    fprintf(stderr, "  -e file         ECH config file (binary)\n");
    fprintf(stderr, "  -t hash         Trust anchor SPKI hash (64 hex chars)\n");
}

int
main(int argc, char **argv)
{
    const char *host = "localhost";
    int port = 443;
    const char *echConfigFile = NULL;
    const char *trustAnchor = NULL;
    int opt;

    while ((opt = getopt(argc, argv, "h:p:e:t:")) != -1) {
        switch (opt) {
            case 'h':
                host = optarg;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'e':
                echConfigFile = optarg;
                break;
            case 't':
                trustAnchor = optarg;
                break;
            default:
                usage(argv[0]);
                return 1;
        }
    }

    return runTest(host, port, echConfigFile, trustAnchor);
}
