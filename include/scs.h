/*
 * (c) KoanLogic Srl - 2011
 */ 

#ifndef _SCS_H_
#define _SCS_H_

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "scs_conf.h"
#include "base64.h"

/* The resulting ciphertext size is computed as the size of the plaintext 
 * extended to the next block. */
#define ENC_LENGTH(inlen, blocklen) \
    ((inlen) + (blocklen) - ((inlen) % (blocklen)))

/* This uses that the expression (n+(k-1))/k means the smallest
 * integer >= n/k, i.e., the ceiling of n/k.  */
#define BASE64_LENGTH(inlen)        \
    ((((inlen) + 2) / 3) * 4)

/* For the default settings used by deflateInit(), the only expansion is an 
 * overhead of five bytes per 16 KB block (about 0.03%), plus a one-time 
 * overhead of six bytes for the entire stream. Even if the last or only block 
 * is smaller than 16 KB, the overhead is still five bytes. 
 * The following macro handles worst case scenario. */
#define COMP_LENGTH(inlen)          \
    ((inlen) + 6 + (5 * (((inlen) % 16384) + 1)))

/* Maximum size of Cookie (TODO shorten to take care of attributes). */
#define SCS_COOKIE_SIZE_MAX 4096

/* Maximum length of various transform identifiers 
 * (TODO override via configure). */
#define SCS_TID_MAX     64
#define SCS_ATIME_MAX   32

typedef enum
{
    SCS_OK = 0,
    SCS_ERR_MEM,                /* Memory exhaustion. */
    SCS_ERR_WRONG_CIPHERSET,    /* Bad cipherset supplied to initialization. */
    SCS_ERR_CRYPTO,             /* Crypto toolkit error. */
    SCS_ERR_OS,                 /* Some syscall has failed. */
    SCS_ERR_COMPRESSION,        /* Compression library error. */
    SCS_ERR_IMPL,               /* Hit an implementation limit. */
    SCS_ERR_DECODE,             /* Failed decoding. */
    SCS_ERR_WRONG_TID,          /* TID not found. */
    SCS_ERR_TAG_MISMATCH,       /* Supplied and computed tags don't match. */
    SCS_ERR_SESSION_EXPIRED     /* session_max_age overrun. */
} scs_err_t;

typedef enum
{
    /* 
     * The only one mandated by the spec: 
     * - key_sz is 16 bytes;
     * - hkey_sz size is 20 bytes.
     */
    AES_128_CBC_HMAC_SHA1    
} scs_cipherset_t;

typedef struct
{
    int active;

    /* Opaque (unique) identifier for the cipherset/keyset in use. */
    char tid[SCS_TID_MAX];

    /* Cipherset identifier. */
    scs_cipherset_t cipherset;
 
    /* Block encryption parameters. */
    size_t key_sz;
    uint8_t key[128];
    size_t block_sz;

    /* HMAC key. */
    size_t hkey_sz;
    uint8_t hkey[128];

    /* Enable/disable compression. */
    int comp;
} scs_keyset_t;

/* 
 * SCS runtime context.
 */
typedef struct
{
    scs_err_t rc;
    char estr[256];

    /* Current and previously active keyset. */
    scs_keyset_t cur_keyset, prev_keyset;

    /* Protocol atoms in raw and Base-64 encoded form. */
    uint8_t *data;
    size_t data_sz, data_capacity;
    char *b64_data;

    uint8_t tag[64];
    size_t tag_sz;
    char b64_tag[BASE64_LENGTH(64) + 1];

    time_t atime, max_session_age;
    char s_atime[SCS_ATIME_MAX];
    char b64_atime[BASE64_LENGTH(SCS_ATIME_MAX) + 1];

    uint8_t iv[128];
    char b64_iv[BASE64_LENGTH(128) + 1];

    char b64_tid[BASE64_LENGTH(SCS_TID_MAX) + 1];
} scs_t;

int scs_init (const char *, scs_cipherset_t, const uint8_t *, const uint8_t *,
        int, time_t, scs_t **pscs);
int scs_encode (scs_t *scs, const uint8_t *state, size_t state_sz);
int scs_decode (scs_t *scs, const char *data, const char *atime, 
        const char *iv, const char *tag, const char *tid,
        uint8_t **pstate, size_t *pstate_sz);
void scs_term (scs_t *scs);

/* TODO getter/setter methods */

#endif  /* !_SCS_H_ */
