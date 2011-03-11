/*
 * (c) KoanLogic Srl - 2011
 */ 

%module scs
%{
#include <scs.h>
%}

typedef char uint8_t;
typedef unsigned int time_t;

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

#ifndef SCS_COOKIE_MAX
  #define SCS_COOKIE_MAX    4096
#endif  /* !SCS_COOKIE_MAX */

#ifndef SCS_TID_AUTO_MAX
  #define SCS_TID_AUTO_LEN  10  /* Length of auto generated TID. */
#endif  /* !SCS_TID_AUTO_MAX */

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
    SCS_ERR_BAD_PAD,            /* Bad padding found while decrypting state. */
    SCS_ERR_FRAMING,            /* Framing error of the SCS cookie. */
    SCS_ERR_BAD_TID,            /* Supplied TID string is too long. */
    SCS_ERR_REFRESH             /* Error refreshing keys. */
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


/** Automatic refresh. */
#define SCS_KEY_AUTO    NULL
#define SCS_TID_AUTO    NULL

/**
 * SCS runtime context.
 */
struct scs_s;   /* Forward decls. */
typedef struct scs_s scs_t;

    /* /swig/ typemaps for scs_init()
     *
     * Return newly allocated SCS object instead of expecting output argument.
     */
    %typemap(in, numinputs=0) scs_t ** (scs_t **ps) {
        $1 = &ps;
    }
    %typemap(argout) scs_t ** {
        char buf[128];
        if (result) {
            snprintf(buf, sizeof(buf), "failed scs_init() (rc=%d)", result);
            SWIG_exception_fail(0, buf);
        }
        $result = SWIG_NewPointerObj(*$1, SWIGTYPE_p_scs_s, 0);
    }

/** Create and configure a new SCS context. */
    %rename scs_init (const char *, scs_cipherset_t, const uint8_t *,
        const uint8_t *, int, time_t, scs_t **) init;
int scs_init (const char *tid, scs_cipherset_t cipherset, const uint8_t *key, 
        const uint8_t *hkey, int comp, time_t max_session_age, scs_t **ps);

    /* \swig\ clear typemaps for scs_init() */
    %clear (scs_t **);

    /* /swig/ typemaps for scs_encode()
     *
     * Cookie parameter not required (buffer is used only internally).
     */
    %typemap(in, numinputs=0) char[SCS_COOKIE_MAX] (char c[SCS_COOKIE_MAX]) {
        $1 = &c;
    }

/** Create SCS cookie to transport \p state data. */
    %rename scs_encode (scs_t *, const uint8_t *,
            size_t, char[SCS_COOKIE_MAX]) encode;
const char *scs_encode (scs_t *ctx, const uint8_t *state, size_t state_sz,
        char cookie[SCS_COOKIE_MAX]);

    /* \swig\ clear typemaps for scs_encode() */
    %clear (scs_t **);

    /* /swig/ typemaps for scs_decode()
     *
     * Don't require output cookie size, but use it to calculate size of
     * returned string.
     */
    %typemap(in, numinputs=0) size_t * (size_t *sz) {
        $1 = &sz;
    }
    %typemap(argout) size_t * (size_t *sz) {
        if (result == NULL)
            SWIG_exception_fail(0, "failed scs_decode()");
        $result = PyString_FromStringAndSize(result, *$1);
    }

/** Decode SCS cookie to retrieve previously saved state data. */
    %rename scs_decode (scs_t *, const char *, size_t *) decode;
void *scs_decode (scs_t *ctx, const char *cookie, size_t *pstate_sz);

    /* \swig\ clear typemaps for scs_decode() */
    %clear (size_t *);

/** Dispose the supplied SCS context. */
    %rename scs_term(scs_t *) term;
void scs_term (scs_t *ctx);

/* Return last error string. */
    %rename scs_err (scs_t *) err;
const char *scs_err (scs_t *ctx);

/** Refresh key material and shift active keyset. */
    %rename scs_refresh_keyset (scs_t *, const char *, const uint8_t *,
        const uint8_t *) refresh_keyset;
int scs_refresh_keyset (scs_t *ctx, const char *new_tid, const uint8_t *key, 
        const uint8_t *hkey);
