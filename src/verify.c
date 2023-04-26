#include "xsmc.h"
#include "xsHost.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include "mbedtls/base64.h"
#include "mbedtls/error.h"

void xs_jwt_verify(xsMachine *the)
{
    mbedtls_pk_context pkey;
    uint8_t *jwt = (uint8_t *)xsmcToString(xsArg(0));
    uint8_t *key;
    size_t key_length;
    int ret = 0;

    xsmcGetBufferReadable(xsArg(1), (void **)&key, &key_length);

    mbedtls_pk_init(&pkey);

    uint8_t *pem_key = malloc(key_length + 1);
    memcpy(pem_key, key, key_length);
    pem_key[key_length] = 0;
    ret = mbedtls_pk_parse_public_key(&pkey, pem_key, key_length + 1);
    free(pem_key);
    if (ret != 0)
    {
        xsResult = xsFalse;
        return;
    }

    const char *header_end = strchr(jwt, '.');
    const char *payload_end = strchr(header_end + 1, '.');
    if (!header_end || !payload_end)
    {
        xsResult = xsFalse;
        return;
    }

    size_t header_len = header_end - (const char *)jwt;
    size_t payload_len = payload_end - (header_end + 1);
    size_t signature_len = strlen(payload_end + 1);

    // Compute the hash of the message, we assume SHA-256
    unsigned char hash[32];
    char message[header_len + 1 + payload_len];
    memcpy(message, jwt, header_len);
    message[header_len] = '.';
    memcpy(message + header_len + 1, header_end + 1, payload_len);
    mbedtls_sha256((unsigned char *)message, header_len + 1 + payload_len, hash, 0);

    // Base64Url decode the signature
    unsigned char *urlsafe_base64 = (unsigned char *)malloc(signature_len + 4); // Allocate extra space for padding
    memcpy(urlsafe_base64, payload_end + 1, signature_len);

    // Replace URL-safe characters '-' -> '+' and '_' -> '/' and add padding
    for (size_t i = 0; i < signature_len; i++)
    {
        if (urlsafe_base64[i] == '-')
            urlsafe_base64[i] = '+';
        else if (urlsafe_base64[i] == '_')
            urlsafe_base64[i] = '/';
    }
    size_t padding = (4 - (signature_len % 4)) % 4;
    for (i = 0; i < padding; i++)
    {
        urlsafe_base64[signature_len + i] = '=';
    }

    size_t decoded_signature_len;
    unsigned char signature[MBEDTLS_MPI_MAX_SIZE];
    ret = mbedtls_base64_decode(signature, MBEDTLS_MPI_MAX_SIZE, &decoded_signature_len, urlsafe_base64, signature_len + padding);
    free(urlsafe_base64);

    // Verify the signature
    xsResult = (mbedtls_pk_verify(&pkey, MBEDTLS_MD_SHA256, hash, 0, signature, decoded_signature_len) == 0) ? xsTrue : xsFalse;
}