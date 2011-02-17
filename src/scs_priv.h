#ifndef _SCS_PRIV_H_
#define _SCS_PRIV_H_

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "scs_conf.h"
#include "scs.h"
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
#define SCS_IV_MAX      128
#define SCS_TAG_MAX     64
#define SCS_DATA_MAX    8192    /* Maximum uncompressed state size. */

/** 
 * Placeholder for keyset configuration data.
 */
typedef struct scs_keyset_s
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

/**
 * SCS protocol atoms in raw and Base-64 encoded form.
 */
typedef struct scs_atoms_s
{
    uint8_t data[SCS_DATA_MAX];
    size_t data_sz;
    char b64_data[BASE64_LENGTH(SCS_DATA_MAX) + 1];

    uint8_t tag[SCS_TAG_MAX];
    size_t tag_sz;
    char b64_tag[BASE64_LENGTH(SCS_TAG_MAX) + 1];

    char atime[SCS_ATIME_MAX];
    char b64_atime[BASE64_LENGTH(SCS_ATIME_MAX) + 1];

    uint8_t iv[SCS_IV_MAX];
    char b64_iv[BASE64_LENGTH(SCS_IV_MAX) + 1];

    char b64_tid[BASE64_LENGTH(SCS_TID_MAX) + 1];
} scs_atoms_t;

/* 
 * SCS runtime context.
 */
struct scs_s
{
    /* Last seen error and corresponding human readable message. */
    scs_err_t rc;
    char estr[256];

    /* Current and previously active keyset. */
    struct scs_keyset_s cur_keyset, prev_keyset;

    time_t max_session_age;

    /* SCS protocol atoms. */
    struct scs_atoms_s atoms;
};

#endif  /* !_SCS_PRIV_H_ */
