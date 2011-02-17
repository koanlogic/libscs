/* (c) KoanLogic Srl - 2011 */ 

#include <assert.h>
#include <stdio.h>
#include <stdlib.h> 
#include <time.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include "scs_conf.h"
#include "scs.h"
#include "utils.h"
#include "base64.h"
#include "scs_priv.h"

#ifdef HAVE_LIBZ
  #include <zlib.h>
#endif  /* HAVE_LIBZ */

#ifdef USE_CYASSL
  #include "cyassl_drv.h"
#elif defined(USE_OPENSSL)
  #include "openssl_drv.h"
#endif  /* USE_CYASSL || USE_OPENSSL */

static struct
{
    int (*init) (void);
    int (*gen_iv) (scs_t *ctx);
    int (*enc) (scs_t *ctx);
    int (*dec) (scs_t *ctx, scs_keyset_t *ks);
    int (*tag) (scs_t *ctx);
    void (*term) (void);
} D = {
#ifdef USE_CYASSL
    cyassl_init,
    cyassl_gen_iv,
    cyassl_enc,
    cyassl_dec,
    cyassl_tag,
    cyassl_term
#elif defined (USE_OPENSSL)
    openssl_init,
    openssl_gen_iv,
    openssl_enc,
    openssl_dec,
    openssl_tag,
    openssl_term
#endif
};

static int init_keyset (scs_keyset_t *ks, const char *tid, int comp,
        scs_cipherset_t cipherset, const uint8_t *key, const uint8_t *hkey);
static void reset_atoms (scs_atoms_t *atoms);

/* Encode support. */
static int get_random_iv (scs_t *ctx);
static int get_atime (scs_t *ctx);
static int optional_compress (scs_t *ctx, const uint8_t *st, size_t st_sz);
static int do_compress (scs_t *ctx, const uint8_t *state, size_t state_sz);
static int encrypt_state (scs_t *ctx);
static int do_pad (scs_t *ctx);
static int create_tag (scs_t *ctx, scs_keyset_t *ks, int skip_encoding);

/* Decode support. */
static scs_keyset_t *retr_keyset (scs_t *ctx, const char *tid);
static int alloc_decoding_dyn_data (scs_t *ctx, size_t b64_state_sz);
int attach_atoms (scs_t *ctx, const char *b64_data, const char *b64_atime, 
        const char *b64_iv, const char *b64_tag);
static int decode_atoms (scs_t *ctx, scs_keyset_t *ks);
static int tags_match (scs_t *ctx, const char *tag);
static int atime_ok (scs_t *ctx);
static int optional_uncompress (scs_t *ctx);
static int decrypt_state (scs_t *ctx, scs_keyset_t *ks);
static int remove_pad (scs_t *ctx);

static void debug_print_buf (const char *label, const uint8_t *b, size_t b_sz);
static void debug_print_cookies (scs_t *ctx);

/**
 *  \brief  Prepare SCS PDU atoms to save the supplied \p state blob 
 *          to remote UA.
 */ 
int scs_encode (scs_t *ctx, const uint8_t *state, size_t state_sz)
{
    scs_atoms_t *ats = &ctx->atoms;
    scs_keyset_t *ks = &ctx->cur_keyset;
    int skip_atoms_encoding = 1;

    reset_atoms(ats);

    /* 1.  iv = RAND()
     * 2.  atime = NOW
     * 3.  data = Enc(Comp(state))
     * 4.  tag = HMAC(e(data)||e(atime)||e(tid)||e(iv)) */
    if (get_random_iv(ctx) 
            || get_atime(ctx) 
            || optional_compress(ctx, state, state_sz) 
            || encrypt_state(ctx) 
            || create_tag(ctx, ks, !skip_atoms_encoding))
    {
        reset_atoms(ats);   /* Remove any garbage. */
        return -1;
    }

    debug_print_cookies(ctx);

    return 0;
}

#if 0
/** \brief  ... */
int scs_decode (scs_t *ctx, const char *data, const char *atime,
        const char *iv, const char *tag, const char *tid)
{
    scs_keyset_t *ks;
    int skip_atoms_encoding = 1;

    reset_atoms(at);

    /* 1.  If (tid is available)
     * 2.      data' = d($SCS_DATA)
     *         atime' = d($SCS_ATIME)
     *         tid' = d($SCS_TID)
     *         iv' = d($SCS_IV)
     *         tag' = d($SCS_AUTHTAG)
     * 3.     tag = HMAC(<data'>||<atime'>||<tid'>||<iv'>)
     * 4.     If (tag == tag' && NOW - atime' <= max_session_age)
     * 5.         state = Uncomp(Dec(data'))
     * 6.     Else discard PDU
     * 7.  Else discard PDU        */
    if ((ks = retr_keyset(ctx, tid)) == NULL 
            || alloc_decoding_dyn_data(ctx, strlen(data))
            || attach_atoms(ctx, data, atime, iv, tag)
            || decode_atoms(ctx, ks)
            || create_tag(ctx, ks, skip_atoms_encoding)
            || tags_match(ctx, tag)
            || atime_ok(ctx)
            || decrypt_state(ctx, ks)
            || optional_uncompress(ctx))
    {
        reset_atoms(at);
        return -1;
    }

    return 0;
}
#endif /* 0 */

/**
 *  \brief  Return an SCS context initialized with the supplied tid, keyset,
 *          cipherset, compression and max age parameters.
 *          Note that the \p tid string must be at least 64 bytes long: longer
 *          strings will be silently truncated.
 *          In case no deflate library has been found during the configuration
 *          stage, the \p comp value will be silently ignored (i.e. always set 
 *          to false). 
 */ 
int scs_init (const char *tid, scs_cipherset_t cipherset, const uint8_t *key, 
        const uint8_t *hkey, int comp, time_t max_session_age, scs_t **ps)
{
    scs_err_t rc;
    scs_t *s = NULL;

    /* Initialize the crypto toolkit. */
    if (D.init() == -1)
        return SCS_ERR_CRYPTO;

    /* Make room for the SCS context structure. */
    if ((s = calloc(1, sizeof *s)) == NULL)
        return SCS_ERR_MEM;

    /* Initialize current keyset. */
    if ((rc = init_keyset(&s->cur_keyset, tid, comp, cipherset, key, hkey)))
    {
        free(s);
        return rc;
    }

    /* Upper bound session lifetime. */
    s->max_session_age = max_session_age;

    /* New SCS context'es have one only active keyset (cur). */
    s->cur_keyset.active = 1;
    s->prev_keyset.active = 0;
    
    /* Initialize error reporting. */
    s->rc = SCS_OK;
    s->estr[0] = '\0';

    /* 
     * Note: .tag_sz will be set by each driver tag() function.
     */

    /* Copy out to the result argument. */
    *ps = s;

    return SCS_OK;
}

/** 
 *  \brief  Dispose memory resources allocated to the supplied SCS context.
 */
void scs_term (scs_t *s)
{
    memset(s, 0, sizeof *s);
    free(s);
    D.term();

    return;
}

/* Let the crypto toolkit handle PR generation of the block cipher IV. */
static int get_random_iv (scs_t *ctx)
{
    /* Crypto driver is in charge of error reporting through scs_set_error(). */
    if (D.gen_iv(ctx) == 0)
        return 0;

    return -1;
}

static int get_atime (scs_t *ctx)
{
    time_t atime;
    char ebuf[128];
    scs_atoms_t *ats = &ctx->atoms;

    if ((atime = time(NULL)) == (time_t) -1)
    {
        (void) strerror_r(errno, ebuf, sizeof ebuf);
        scs_set_error(ctx, SCS_ERR_OS, "time(3) failed: %s", ebuf);
        return -1;
    }

#ifdef FIXED_PARAMS
    strcpy(ats->atime, "123456789");
#endif  /* FIXED_PARAMS */

    /* Get string representation of atime which will be used later on when 
     * creating the authentication tag. */
    if (snprintf(ats->atime, sizeof ats->atime, 
                "%"PRIdMAX, (intmax_t) atime) >= (int) sizeof ats->atime)
    {
        scs_set_error(ctx, SCS_ERR_IMPL, "inflate SCS_ATIME_MAX !");
        return -1;
    }

    return 0;
}

static int optional_compress (scs_t *ctx, const uint8_t *state, size_t state_sz)
{
    scs_atoms_t *ats = &ctx->atoms;
    scs_keyset_t *ks = &ctx->cur_keyset;

    if (ks->comp)
    {
        ats->data_sz = state_sz;
        memcpy(ats->data, (uint8_t *) state, ats->data_sz);
        return 0;
    }

    /* Set it to the maximum available, it will be updated later on 
     * by do_compress(). */
    ats->data_sz = sizeof ats->data;

    return do_compress(ctx, state, state_sz);
}

static int encrypt_state (scs_t *ctx)
{
    /* Pad data to please the block encyption cipher, if needed, then 
     * encrypt. */
    if (do_pad(ctx)
            || D.enc(ctx))
        return -1;

    return 0;
}

static int create_tag (scs_t *ctx, scs_keyset_t *ks, int skip_encoding)
{
    size_t i;
    scs_atoms_t *ats = &ctx->atoms;
    enum { NUM_ATOMS = 4 };
    struct {
        char *raw, *enc;
        size_t raw_sz, enc_sz;
    } A[NUM_ATOMS] = {
        { 
            (char *) ats->data,
            ats->b64_data,
            ats->data_sz,
            BASE64_LENGTH(ats->data_sz)
        },
        { 
            ats->atime,
            ats->b64_atime,
            strlen(ats->atime),
            sizeof(ats->b64_atime)
        },
        {
            ks->tid,
            ats->b64_tid,
            strlen(ks->tid),
            sizeof(ats->b64_tid)
        },
        {
            (char *) ats->iv,
            ats->b64_iv,
            ks->block_sz,
            BASE64_LENGTH(ks->block_sz)
        }
    };    
    
    /* If requested, create Base-64 encoded versions of atoms. */
    if (!skip_encoding)
    {
        for (i = 0; i < NUM_ATOMS; ++i)
            base64_encode(A[i].raw, A[i].raw_sz, A[i].enc, A[i].enc_sz);
    }
        
    /* Create auth tag. */
    if (D.tag(ctx))
        return -1;

    /* Base-64 encode the auth tag. */
    base64_encode((const char *) ats->tag, ats->tag_sz, 
            ats->b64_tag, sizeof ats->b64_tag);

    return 0;
}

/* Reset protocol atoms values. */
static void reset_atoms (scs_atoms_t *ats)
{
    memset(ats, 0, sizeof *ats); 
    return;
}

/* Zlib's compression method, an LZ77 variant called deflation, emits 
 * compressed data as a sequence of blocks.  Various block types are allowed, 
 * one of which is stored blocks -- these are simply composed of the raw input 
 * data plus a few header bytes.  In the worst possible case, where the other 
 * block types would expand the data, deflation falls back to stored 
 * (uncompressed) blocks.  Thus for the default settings used by deflateInit(), 
 * compress(), and compress2(), the only expansion is an overhead of five bytes
 * per 16 KB block (about 0.03%), plus a one-time overhead of six bytes for the
 * entire stream.  Even if the last or only block is smaller than 16 KB, the 
 * overhead is still five bytes.  In the absolute worst case of a single-byte 
 * input stream, the overhead therefore amounts to 1100% (eleven bytes of 
 * overhead, one byte of actual data).  For larger stream sizes, the overhead 
 * approaches the limiting value of 0.03%.  */
//static int compress (const char *in, uint8_t *out, size_t *pout_sz)
static int do_compress (scs_t *ctx, const uint8_t *state, size_t state_sz)
{
#ifdef HAVE_LIBZ
    int ret;
    z_stream zstr;
    scs_atoms_t *ats = &ctx->atoms;

    zstr.zalloc = Z_NULL;
    zstr.zfree = Z_NULL;
    zstr.opaque = Z_NULL;

    if ((ret = deflateInit(&zstr, Z_DEFAULT_COMPRESSION)) != Z_OK)
    {
        scs_set_error(ctx, SCS_ERR_COMPRESSION, "zlib error: %s", zError(ret));
        return -1;
    }

    zstr.next_in = (Bytef *) state;
    zstr.avail_in = state_sz;

    zstr.next_out = ats->data;
    zstr.avail_out = ats->data_sz;

    /* We can't overflow the output buffer as long as '*pout_sz' is the
     * real size of 'out'. */
    if ((ret = deflate(&zstr, Z_FINISH)) != Z_STREAM_END)
    {
        scs_set_error(ctx, SCS_ERR_COMPRESSION, "zlib error: %s", zError(ret));
        goto err; 
    }

    ats->data_sz = zstr.total_out;

    deflateEnd(&zstr);

    return 0;
err:
    deflateEnd(&zstr);
    return -1;
#else
    assert(!"I'm not supposed to get there without zlib...");
#endif  /* HAVE_LIBZ */
}

static int do_pad (scs_t *ctx)
{
    scs_atoms_t *ats = &ctx->atoms;
    scs_keyset_t *ks = &ctx->cur_keyset;
    size_t pad_len, *sz;
   
    sz = &ats->data_sz;

    pad_len = ks->block_sz - (*sz % ks->block_sz);

    /* RFC 3852, Section 6.3: "This padding method is well defined if 
     * and only if k (i.e. pad_len) is less than 256." */
    if (pad_len >= 256)
    {
        scs_set_error(ctx, SCS_ERR_IMPL, "unsupported pad length");
        return -1;
    }

    if (*sz + pad_len > sizeof ats->data)
    {
        scs_set_error(ctx, SCS_ERR_IMPL, "data buffer too small");
        return -1;
    }

    if (pad_len)
    {
        /* If the length of (compressed) state is not a multiple of the 
         * block size, its value will be filled with padding bytes of equal 
         * value as the pad length. */
        memset(ats->data + *sz, pad_len, pad_len);
        *sz += pad_len;
    }

    return 0;
}

static void debug_print_buf (const char *label, const uint8_t *b, size_t b_sz)
{
    unsigned int i;

    printf("<%s>", label);
    for (i = 0; i < b_sz; ++i)
    {
        if (i % 8 == 0)
            printf("\n");

        printf("%02x ", b[i]);
    }
    printf("\n</%s>\n", label);
}

static int init_keyset (scs_keyset_t *ks, const char *tid, int comp,
        scs_cipherset_t cipherset, const uint8_t *key, const uint8_t *hkey)
{
    scs_err_t rc;

    /* Silently truncate tid if longer than sizeof ks->tid (64 bytes). */
    (void) snprintf(ks->tid, sizeof ks->tid, "%s", tid);

    /* Set the compression flag as requested.  In case zlib is not available 
     * on the platform, ignore user request and set to false. */
#ifdef HAVE_LIBZ
    ks->comp = comp;
#else
    ks->comp = 0;
#endif  /* HAVE_LIBZ */

    /* Setup keyset and cipherset. */
    switch ((ks->cipherset = cipherset))
    {
        case AES_128_CBC_HMAC_SHA1:
            ks->key_sz = ks->block_sz = 16;
            ks->hkey_sz = 20;
            break;
        default:
            rc = SCS_ERR_WRONG_CIPHERSET;
            goto err;
    }

    /* Internalise keying material. */
    memcpy(ks->key, key, ks->key_sz);
    memcpy(ks->hkey, hkey, ks->hkey_sz);

    return SCS_OK;
err:
    return rc;
}

#if 0
/* Possible truncation will be detected in some later processing stage. */
int attach_atoms (scs_t *ctx, const char *b64_data, const char *b64_atime, 
        const char *b64_iv, const char *b64_tag)
{
    /* SCS_DATA */
//    ctx->data_sz = strlen(b64_data);
    memcpy(ctx->data, b64_data, ctx->data_sz);

    /* SCS_ATIME */
    (void) snprintf(ctx->b64_atime, sizeof ctx->b64_atime, "%s", b64_atime);

    /* SCS_IV */
    (void) snprintf(ctx->b64_iv, sizeof ctx->b64_iv, "%s", b64_iv);

    /* SCS_AUTHTAG */
    (void) snprintf(ctx->b64_tag, sizeof ctx->b64_tag, "%s", b64_tag);

    return 0;
}

/* Note that tid has been already decoded in order to identify the running
 * keyset inside retr_keyset().  Its value is found in the selected keyset. */
static int decode_atoms (scs_t *ctx, scs_keyset_t *ks)
{
    size_t i, atime_sz = sizeof(ctx->atime), iv_sz = ks->block_sz;
    enum { NUM_ATOMS = 4 };
    struct {
        const char *id;
        char *raw;
        size_t *raw_sz;
        const char *enc;
        size_t enc_sz;
    } A[NUM_ATOMS] = {
        {
            "SCS_DATA",
            (char *) ctx->data,
            &ctx->data_sz,      /* Initially set to data_capacity. */
            ctx->b64_data,
            strlen(ctx->b64_data)
        },
        {
            "SCS_ATIME",
            &ctx->atime[0],
            &atime_sz,
            ctx->b64_atime,
            strlen(ctx->b64_atime)
        },
        {
            "SCS_IV",
            (char *) ctx->iv,
            &iv_sz,
            ctx->b64_iv,
            strlen(ctx->b64_iv)
        },
        {
            "SCS_AUTHTAG",
            (char *) ctx->tag,
            &ctx->tag_sz,
            ctx->b64_tag,
            strlen(ctx->b64_tag)
        }
    };

    for (i = 0; i < NUM_ATOMS; ++i)
    {
        if (!base64_decode(A[i].enc, A[i].enc_sz, A[i].raw, A[i].raw_sz))
        {
            scs_set_error(ctx, SCS_ERR_DECODE, "%s decoding failed", A[i].id);
            return -1;
        }
    }

    return 0;
}

static scs_keyset_t *retr_keyset (scs_t *ctx, const char *tid)
{
    char raw_tid[SCS_TID_MAX];
    size_t raw_tid_len = sizeof raw_tid - 1;

    /* Make sure we have room for the terminating NUL char. */
    if (!base64_decode(tid, strlen(tid), raw_tid, &raw_tid_len))
    {
        scs_set_error(ctx, SCS_ERR_DECODE, "Base-64 decoding of tid failed");
        return NULL;
    }

    raw_tid[raw_tid_len] = '\0';

    if (ctx->cur_keyset.active && !strcmp(raw_tid, ctx->cur_keyset.tid))
        return &ctx->cur_keyset;

    if (ctx->prev_keyset.active && !strcmp(raw_tid, ctx->prev_keyset.tid))
        return &ctx->prev_keyset;

    scs_set_error(ctx, SCS_ERR_WRONG_TID, "tid %s not found", raw_tid);
    return NULL;
}

static int alloc_decoding_dyn_data (scs_t *ctx, size_t b64_state_sz)
{
    char ebuf[128];

    ctx->b64_data = NULL;   /* Unused when decoding. */
    ctx->data_sz = ctx->data_capacity = SCS_STATE_MAX;

    if ((ctx->data = calloc(1, ctx->data_capacity)) == NULL)
    {
        (void) strerror_r(errno, ebuf, sizeof ebuf);
        (void) scs_set_error(ctx, SCS_ERR_OS, "calloc(3) failed: %s", ebuf);
        return -1;
    }

    return 0;
}

static int tags_match (scs_t *ctx, const char *tag)
{
    if (!strcmp(ctx->b64_tag, tag))
        return 0;

    scs_set_error(ctx, SCS_ERR_TAG_MISMATCH, 
            "\'%s\' != \'%s\'", ctx->b64_tag, tag);

    return -1;
}

static int atime_ok (scs_t *ctx)
{
    char ebuf[128];
    time_t now, atime, delta;

    if ((now = time(NULL)) == (time_t) -1)
    {
        (void) strerror_r(errno, ebuf, sizeof ebuf);
        scs_set_error(ctx, SCS_ERR_OS, "time(3) failed: %s", ebuf);
        return -1;
    }

    /* Get time_t representation of atime (XXX do it better). */
    atime = (time_t) atoi(ctx->atime);

    if ((delta = (now - atime)) <= ctx->max_session_age)
        return 0;

    scs_set_error(ctx, SCS_ERR_SESSION_EXPIRED, 
            "session expired %"PRIdMAX" seconds ago", 
            (intmax_t) (delta - ctx->max_session_age));

    return -1;
}

static int decrypt_state (scs_t *ctx, scs_keyset_t *ks)
{
    /* Decrypt and remove padding, if any. */
    if (D.dec(ctx, ks)
            || remove_pad(ctx))
        return -1;

    return 0;
}

static int remove_pad (scs_t *ctx)
{
    return 0;
}

static int optional_uncompress (scs_t *ctx)
{
    return 0;
}
#endif

static void debug_print_cookies (scs_t *ctx)
{
    scs_atoms_t *ats = &ctx->atoms;

    printf("SCS_ATIME = %s\n", ats->b64_atime);
    printf("SCS_AUTHTAG = %s\n", ats->b64_tag);
    printf("SCS_DATA = %s\n", ats->b64_data);
    printf("SCS_TID = %s\n", ats->b64_tid);
    printf("SCS_IV = %s\n", ats->b64_iv);

    return;
}
