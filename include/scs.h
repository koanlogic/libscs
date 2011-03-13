/*
 * (c) KoanLogic Srl - 2011
 */ 

#ifndef _SCS_H_
#define _SCS_H_

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

struct scs_s;   /* Forward decl. */

/**
 *  \addtogroup scs
 *  \{
 */

/*
 * Maximum length of various transform identifiers.
 * May be overwritten at configuration time, e.g.: 
 *      $ makl-conf --extra-cflags="-DSCS_DATA_MAX=16384 -DSCS_TID_MAX=32"
 * to double the SCS_DATA_MAX parameter and halve the TID.
 */ 
#ifndef SCS_TID_MAX
  /** Maximum length of the Transform IDentifier string. */
  #define SCS_TID_MAX   64
#endif  /* !SCS_TID_MAX */

#ifndef SCS_TSTAMP_MAX
  /** Maximum length of the TSTAMP string. */
  #define SCS_TSTAMP_MAX 32
#endif  /* !SCS_TSTAMP_MAX */

#ifndef SCS_IV_MAX
  /** Maximum length of the Initialization Vector field. */
  #define SCS_IV_MAX    128
#endif  /* !SCS_IV_MAX */

#ifndef SCS_TAG_MAX
  /** Maximum length of the AUTHTAG field. */
  #define SCS_TAG_MAX   64
#endif  /* !SCS_TAG_MAX */

#ifndef SCS_DATA_MAX
  /** Maximum size for the uncompressed state blob. */
  #define SCS_DATA_MAX  8192    
#endif  /* !SCS_DATA_MAX */

#ifndef SCS_COOKIE_MAX
  /** Maximum size for the produced / consumed SCS cookie. */
  #define SCS_COOKIE_MAX    4096
#endif  /* !SCS_COOKIE_MAX */

#ifndef SCS_TID_AUTO_MAX
  /** Length of internally generated TIDs. */
  #define SCS_TID_AUTO_LEN  10  
#endif  /* !SCS_TID_AUTO_MAX */

/* Error codes. */
typedef enum
{
    SCS_OK = 0,
    /**< LibSCS did what expected. */

    SCS_ERR_MEM,
    /**< Memory exhaustion. */

    SCS_ERR_WRONG_CIPHERSET,
    /**< Bad ::scs_cipherset_t value supplied to scs_init(). */

    SCS_ERR_CRYPTO,
    /**< Error is coming from the crypto toolkit.  
     *   Precise failure cause can be inspected via ::scs_err(). */

    SCS_ERR_OS,
    /**< Some syscall has failed (see ::scs_err() for details.) */

    SCS_ERR_COMPRESSION,
    /**< Compression library error. */

    SCS_ERR_IMPL,
    /**< Hit an implementation limit. */

    SCS_ERR_DECODE,
    /**< Failed SCS cookie decoding. */

    SCS_ERR_ENCODE,
    /**< Failed SCS cookie encoding. */

    SCS_ERR_WRONG_TID,
    /**< TID not found. */

    SCS_ERR_TAG_MISMATCH,
    /**< Supplied and computed authentication tags don't match. */

    SCS_ERR_SESSION_EXPIRED,
    /**< \c session_max_age overrun. */

    SCS_ERR_BAD_PAD,
    /**< Bad padding found after decrypting the DATA field. */

    SCS_ERR_FRAMING,
    /**< Some kind of framing inconsistency was found while trying to decode 
     *   the SCS cookie. */

    SCS_ERR_BAD_TID,
    /**< TID string supplied to is too long (adjust ::SCS_TID_MAX if needed.) */

    SCS_ERR_REFRESH
    /**< Something went wrong while refreshing the keyset. */
} scs_err_t;

/**
 * List of available ciphersets.
 */ 
typedef enum
{
    AES_128_CBC_HMAC_SHA1
    /**< 
     * AES CBC with 128 bit key + HMAC SHA1 is the only cipherset mandated 
     * by the spec.  Encryption key size is 16 bytes, authentication key 
     * size is 20 bytes.  The two keys must be generated independently.
     */
} scs_cipherset_t;


/** Automatic key refresh parameter to ::scs_refresh_keyset(). */
#define SCS_KEY_AUTO    NULL

/** Automatic TID refresh parameter to ::scs_refresh_keyset(). */
#define SCS_TID_AUTO    NULL

/** Compression. */
enum {
    SCS_DO_NOT_COMPRESS = 0,
    SCS_DO_COMPRESS
};

/** SCS runtime context.  */
typedef struct scs_s scs_t;

/* Create and configure a new SCS context. */
int scs_init (const char *tid, scs_cipherset_t cipherset, const uint8_t *key, 
        const uint8_t *hkey, int comp, time_t max_session_age, scs_t **ps);

/* Create SCS cookie to transport \p state data. */
const char *scs_encode (scs_t *ctx, const uint8_t *state, size_t state_sz,
        char cookie[SCS_COOKIE_MAX]);

/* Decode SCS cookie to retrieve previously saved state data. */
void *scs_decode (scs_t *ctx, const char *cookie, size_t *pstate_sz);

/* Dispose the supplied SCS context. */
void scs_term (scs_t *ctx);

/* Return last error string. */
const char *scs_err (scs_t *ctx);

/* Refresh the key material and shift the active keyset. */
int scs_refresh_keyset (scs_t *ctx, const char *new_tid, const uint8_t *key, 
        const uint8_t *hkey);

/* Set auto-refresh policy parameters. */
int scs_auto_refresh_setup (scs_t *ctx, time_t refresh_freq, time_t expiry);

/**
 *  \}
 */ 

#ifdef __cplusplus
}
#endif

#endif  /* !_SCS_H_ */
