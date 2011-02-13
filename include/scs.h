/*
 * (c) KoanLogic Srl - 2011
 */ 

#ifndef _SCS_H_
#define _SCS_H_

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "conf.h"

/* Maximum sizeof Cookie (TODO shorten to take care of attributes). */
#define SCS_COOKIE_SIZE_MAX 4096

typedef enum
{
    SCS_OK = 0,
    SCS_ERR_MEM,                /* Memory exhaustion. */
    SCS_ERR_WRONG_CIPHERSET,    /* Bad cipherset supplied to initialization. */
    SCS_ERR_CRYPTO,             /* Crypto toolkit error. */
    SCS_ERR_OS,                 /* OS error. */
    SCS_ERR_COMPRESSION         /* Compression library error. */
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
    int avail;

    /* Opaque (unique) identifier for the cipherset/keyset in use. */
    char tid[64];   

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
    /* Current and previously active keyset. */
    scs_keyset_t cur_keyset, prev_keyset;

    /* Protocol atoms. */
    uint8_t *data;
    size_t data_sz, data_capacity;

    uint8_t tag[64];
    size_t tag_sz;

    time_t atime, max_session_age;
    char atime_s[32];

    uint8_t iv[128];
} scs_t;

int scs_init (const char *, scs_cipherset_t, const uint8_t *, const uint8_t *,
        int, time_t, scs_t **);
void scs_term (scs_t *);
int scs_inbound (scs_t *);
int scs_outbound (scs_t *, const char *);
void scs_reset_atoms (scs_t *);

/* TODO getter/setter methods */

#endif  /* !_SCS_H_ */
