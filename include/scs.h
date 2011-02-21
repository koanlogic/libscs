/*
 * (c) KoanLogic Srl - 2011
 */ 

#ifndef _SCS_H_
#define _SCS_H_

#include <stddef.h>
#include <stdint.h>
#include <time.h>

/**
 * Maximum length of various transform identifiers.
 * May be overwritten at configuration time, e.g.: 
 *      $ makl-conf --extra-cflags="-DSCS_DATA_MAX=16384 -DSCS_TID_MAX=32"
 * to double the SCS_DATA_MAX parameter and halve the TID.
 */ 
#ifndef SCS_TID_MAX
  #define SCS_TID_MAX   64
#endif  /* !SCS_TID_MAX */

#ifndef SCS_ATIME_MAX
  #define SCS_ATIME_MAX 32
#endif  /* !SCS_ATIME_MAX */

#ifndef SCS_IV_MAX
  #define SCS_IV_MAX    128
#endif  /* !SCS_IV_MAX */

#ifndef SCS_TAG_MAX
  #define SCS_TAG_MAX   64
#endif  /* !SCS_TAG_MAX */

#ifndef SCS_DATA_MAX
  #define SCS_DATA_MAX  8192    /* Maximum uncompressed state size. */
#endif  /* !SCS_DATA_MAX */

/** 
 * Error codes. 
 */
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
    SCS_ERR_ENCODE,             /* Failed encoding. */
    SCS_ERR_WRONG_TID,          /* TID not found. */
    SCS_ERR_TAG_MISMATCH,       /* Supplied and computed tags don't match. */
    SCS_ERR_SESSION_EXPIRED,    /* "session_max_age" overrun. */
    SCS_ERR_BAD_PAD             /* Bad padding found while decrypting state. */
} scs_err_t;

/**
 * List of available ciphersets.
 */ 
typedef enum
{
    /* 
     * AES CBC with 128 bit key + HMAC SHA1 is the only cipherset mandated 
     * by the spec.  Encryption key size is 16 bytes, authentication key 
     * size is 20 bytes.  The two keys must be generated independently.
     */
    AES_128_CBC_HMAC_SHA1    
} scs_cipherset_t;

/**
 * SCS runtime context.
 */
struct scs_s;   /* Forward decls. */
typedef struct scs_s scs_t;


/** Create and configure a new SCS context. */
int scs_init (const char *tid, scs_cipherset_t cipherset, const uint8_t *key, 
        const uint8_t *hkey, int comp, time_t max_session_age, scs_t **ps);

/** Create SCS atoms to transport \p state data. */
int scs_encode (scs_t *ctx, const uint8_t *state, size_t state_sz);

/** Decode SCS atoms to retrieve previously saved state data. */
int scs_decode (scs_t *ctx, const char *data, const char *atime, 
        const char *iv, const char *tag, const char *tid);

/** Dispose the supplied SCS context. */
void scs_term (scs_t *ctx);

/** Getter methods for base-64 (i.e. cookie ready) atoms. */
const char *scs_cookie_data (scs_t *ctx);
const char *scs_cookie_atime (scs_t *ctx);
const char *scs_cookie_iv (scs_t *ctx);
const char *scs_cookie_authtag (scs_t *ctx);
const char *scs_cookie_tid (scs_t *ctx);

/** Getter method for raw, clear-text state data and size. */
const uint8_t *scs_state (scs_t *ctx, size_t *pstate_sz);
size_t scs_state_sz (scs_t *ctx);
 
#endif  /* !_SCS_H_ */
