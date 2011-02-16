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
#ifdef HAVE_LIBZ
  #include <zlib.h>
#endif  /* HAVE_LIBZ */

#ifdef USE_CYASSL
  #include "cyassl_drv.h"
#elif defined(USE_OPENSSL)
  #include "openssl_drv.h"
#endif  /* USE_CYASSL | USE_OPENSSL */

static struct
{
    int (*init) (void);
    int (*gen_iv) (scs_t *scs);
    int (*enc) (scs_t *scs);
    int (*tag) (scs_t *scs);
    void (*term) (void);
} D = {
#ifdef USE_CYASSL
    cyassl_init,
    cyassl_gen_iv,
    cyassl_enc,
    cyassl_tag,
    cyassl_term
#elif defined (USE_OPENSSL)
    openssl_init,
    openssl_gen_iv,
    openssl_enc,
    openssl_tag,
    openssl_term
#endif
};

static int init_keyset (scs_keyset_t *keyset, const char *tid, 
        scs_cipherset_t cipherset, const uint8_t *key, const uint8_t *hkey, 
        int comp);
static void reset_atoms (scs_t *scs);

/* Encode support. */
static int get_random_iv (scs_t *scs);
static int get_atime (scs_t *scs);
static int alloc_dyn_data (scs_t *scs, size_t st_sz);
static int optional_compress (scs_t *scs, const uint8_t *st, size_t st_sz);
static int do_compress (scs_t *scs, const uint8_t *state, size_t state_sz);
static int encrypt_state (scs_t *scs);
static int do_pad (scs_t *scs);
static int create_tag (scs_t *scs, scs_keyset_t *ks);

/* Decode support. */
static scs_keyset_t *retr_keyset (scs_t *scs, const char *tid);
static int decode_atoms (scs_t *scs, const char *b64_data, 
        const char *b64_atime, const char *b64_iv, const char *b64_tag,
        const char *b64_tid);
static int tags_match (scs_t *scs, const char *tag);
static int atime_ok (scs_t *scs);
static int optional_uncompress (scs_t *scs);
static int decode_state (scs_t *scs, scs_keyset_t *ks, uint8_t **pstate, 
        size_t *pstate_sz);

static void debug_print_buf (const char *label, const uint8_t *b, size_t b_sz);
static void debug_print_cookies (scs_t *scs);

/**
 *  \brief  Prepare SCS PDU atoms to save the supplied \p state blob 
 *          to remote UA.
 */ 
int scs_encode (scs_t *scs, const uint8_t *state, size_t state_sz)
{
    scs_keyset_t *ks = &scs->cur_keyset;

    reset_atoms(scs);

    /* 1.  iv = RAND()
     * 2.  atime = NOW
     * 3.  data = Enc(Comp(state))
     * 4.  tag = HMAC(e(data)||e(atime)||e(tid)||e(iv)) */
    if (get_random_iv(scs) 
            || get_atime(scs) 
            || alloc_dyn_data(scs, state_sz) 
            || optional_compress(scs, state, state_sz) 
            || encrypt_state(scs) 
            || create_tag(scs, ks))
    {
        reset_atoms(scs);   /* Remove any garbage. */
        return -1;
    }

    debug_print_cookies(scs);

    return 0;
}

/** \brief  ... */
int scs_decode (scs_t *scs, const char *data, const char *atime,
        const char *iv, const char *tag, const char *tid,
        uint8_t **pstate, size_t *pstate_sz)
{
    scs_keyset_t *ks;

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
    if ((ks = retr_keyset(scs, tid)) == NULL 
            || decode_atoms(scs, data, atime, iv, tag, tid)
            || create_tag(scs, ks)
            || tags_match(scs, tag)
            || atime_ok(scs)
            || optional_uncompress(scs)
            || decode_state(scs, ks, pstate, pstate_sz))
    {
        reset_atoms(scs);
        return -1;
    }

    return 0;
}

/**
 *  \brief  Return an SCS context initialized with the supplied tid, keyset,
 *          cipherset, compression and max age parameters.
 *          Note that the \p tid string must be at least 64 bytes long: longer
 *          strings will be silently truncated.
 *          In case no deflate library has been found during the configuration
 *          stage, the \p comp value will be silently ignored (always set to 
 *          false). 
 */ 
int scs_init (const char *tid, scs_cipherset_t cipherset, const uint8_t *key, 
        const uint8_t *hkey, int comp, time_t max_session_age, scs_t **ps)
{
    scs_t *s = NULL;
    scs_err_t rc;

    /* TODO check preconditions. */

    /* Initialize the crypto toolkit. */
    if (D.init() == -1)
        return SCS_ERR_CRYPTO;

    /* Make room for the SCS context structure. */
    if ((s = calloc(1, sizeof *s)) == NULL)
        return SCS_ERR_MEM;

    /* Initialize current keyset. */
    rc = init_keyset(&s->cur_keyset, tid, cipherset, key, hkey, comp);
    if (rc != SCS_OK)
        goto err;

    s->max_session_age = max_session_age;

    /* Initialize the .data* fields explicitly, so that free(3) won't die on 
     * reset_atoms(). */
    s->data = NULL;
    s->b64_data = NULL;

    s->cur_keyset.active = 1;
    s->prev_keyset.active = 0;
    
    /* Error reporting. */
    s->rc = SCS_OK;
    s->estr[0] = '\0';

    /* Note: .tag_sz will be set by each driver tag() function. */

    /* Copy out to the result argument. */
    *ps = s;

    return SCS_OK;
err:
    free(s);
    return rc;
}

/** 
 *  \brief  Dispose memory resources allocated to the supplied SCS context.
 */
void scs_term (scs_t *s)
{
    if (s)
    {
        /* XXX secure key deletion of keying material ? */
        free(s->data);
        free(s->b64_data);
        free(s);
    }

    D.term();

    return;
}

/* Let the crypto toolkit handle PR generation of the block cipher IV. */
static int get_random_iv (scs_t *scs)
{
    /* Crypto driver is in charge of error reporting through scs_set_error(). */
    if (D.gen_iv(scs) == 0)
        return 0;

    return -1;
}

static int get_atime (scs_t *scs)
{
    char ebuf[128];

    if ((scs->atime = time(NULL)) == (time_t) -1)
    {
        (void) strerror_r(errno, ebuf, sizeof ebuf);
        scs_set_error(scs, SCS_ERR_OS, "time(3) failed: %s", ebuf);
        return -1;
    }

#ifdef FIXED_PARAMS
    scs->atime = 123456789;
#endif  /* FIXED_PARAMS */

    /* Get string representation of atime which will be used later on when 
     * creating the authentication tag. */
    if (snprintf(scs->s_atime, sizeof scs->s_atime, 
                "%"PRIdMAX, (intmax_t) scs->atime) >= (int) sizeof scs->s_atime)
    {
        scs_set_error(scs, SCS_ERR_IMPL, "inflate SCS_ATIME_MAX !");
        return -1;
    }

    return 0;
}

static int alloc_dyn_data (scs_t *scs, size_t state_sz)
{
    size_t b64_data_sz;
    char ebuf[128];
    scs_keyset_t *ks = &scs->cur_keyset;

    /* Make room for the working buf, taking care for IV, padding and potential
     * expansion due to compress overhead (worst case). */
    scs->data_capacity = ENC_LENGTH(COMP_LENGTH(state_sz), ks->block_sz);

    /* Also prepare the Base-64 encoding buffer. */
    b64_data_sz = BASE64_LENGTH(scs->data_capacity) + 1;

    if ((scs->data = calloc(1, scs->data_capacity)) == NULL 
            || (scs->b64_data = calloc(1, b64_data_sz)) == NULL)
    {
        (void) scs_set_error(scs, SCS_ERR_OS, "malloc(3) failed: %s", ebuf);
        return -1;
    }

    return 0;
}

static int optional_compress (scs_t *scs, const uint8_t *state, size_t state_sz)
{
    if (scs->cur_keyset.comp)
    {
        scs->data_sz = state_sz;
        memcpy(scs->data, (uint8_t *) state, scs->data_sz);
        return 0;
    }

    scs->data_sz = scs->data_capacity;

    return do_compress(scs, state, state_sz);
}

static int encrypt_state (scs_t *scs)
{
    /* Pad data to please the block encyption cipher, if needed, then 
     * encrypt. */
    if (do_pad(scs) 
            || D.enc(scs))
        return -1;

    return 0;
}

static int create_tag (scs_t *scs, scs_keyset_t *ks)
{
    size_t i;
    enum { NUM_ATOMS = 4 };
    struct {
        char *raw, *enc;
        size_t raw_sz, enc_sz;
    } A[NUM_ATOMS] = {
        { 
            (char *) scs->data,
            scs->b64_data,
            scs->data_sz,
            BASE64_LENGTH(scs->data_sz)
        },
        { 
            scs->s_atime,
            scs->b64_atime,
            strlen(scs->s_atime),
            sizeof(scs->b64_atime)
        },
        {
            ks->tid,
            scs->b64_tid,
            strlen(ks->tid),
            sizeof(scs->b64_tid)
        },
        {
            (char *) scs->iv,
            scs->b64_iv,
            ks->block_sz,
            BASE64_LENGTH(ks->block_sz)
        }
    };    
    
    /* Create Base-64 encoded versions of atoms. */
    for (i = 0; i < NUM_ATOMS; ++i)
        base64_encode(A[i].raw, A[i].raw_sz, A[i].enc, A[i].enc_sz);
        
    /* Create auth tag. */
    if (D.tag(scs))
        return -1;

    /* Base-64 encode the auth tag. */
    base64_encode((const char *) scs->tag, scs->tag_sz, 
            scs->b64_tag, sizeof scs->b64_tag);

    return 0;
}

/* Reset protocol atoms values. */
static void reset_atoms (scs_t *scs)
{
    if (scs == NULL)
        return;

    free(scs->data), scs->data = NULL;
    free(scs->b64_data), scs->b64_data = NULL;
    scs->data_sz = scs->data_capacity = 0;
    scs->tag_sz = 0;
    scs->atime = (time_t) -1;
    /* TODO */

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
static int do_compress (scs_t *scs, const uint8_t *state, size_t state_sz)
{
#ifdef HAVE_LIBZ
    int ret;
    z_stream zstr;

    zstr.zalloc = Z_NULL;
    zstr.zfree = Z_NULL;
    zstr.opaque = Z_NULL;

    if ((ret = deflateInit(&zstr, Z_DEFAULT_COMPRESSION)) != Z_OK)
    {
        scs_set_error(scs, SCS_ERR_COMPRESSION, "zlib error: %s", zError(ret));
        return -1;
    }

    zstr.next_in = (Bytef *) state;
    zstr.avail_in = state_sz;

    zstr.next_out = scs->data;
    zstr.avail_out = scs->data_sz;

    /* We can't overflow the output buffer as long as '*pout_sz' is the
     * real size of 'out'. */
    if ((ret = deflate(&zstr, Z_FINISH)) != Z_STREAM_END)
    {
        scs_set_error(scs, SCS_ERR_COMPRESSION, "zlib error: %s", zError(ret));
        goto err; 
    }

    scs->data_sz = zstr.total_out;

    deflateEnd(&zstr);

    return 0;
err:
    deflateEnd(&zstr);
    return -1;
#else
    assert(!"I'm not supposed to get there without zlib...");
#endif  /* HAVE_LIBZ */
}

static int do_pad (scs_t *scs)
{
    uint8_t *b;
    size_t block_sz, capacity, pad_len, *sz;
   
    block_sz = scs->cur_keyset.block_sz;
    capacity = scs->data_capacity;
    sz = &scs->data_sz;

    pad_len = block_sz - (*sz % block_sz);

    b = scs->data;

    /* RFC 3852, Section 6.3: "This padding method is well defined if 
     * and only if k (i.e. pad_len) is less than 256." */
    if (pad_len >= 256)
    {
        scs_set_error(scs, SCS_ERR_IMPL, "unsupported pad length");
        return -1;
    }

    if (*sz + pad_len > capacity)
    {
        scs_set_error(scs, SCS_ERR_MEM, "data buffer too small");
        return -1;
    }

    if (pad_len)
    {
        /* If the length of (compressed) state is not a multiple of the 
         * block size, its value will be filled with padding bytes of equal 
         * value as the pad length. */
        memset(b + *sz, pad_len, pad_len);
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

static int init_keyset (scs_keyset_t *keyset, const char *tid, 
        scs_cipherset_t cipherset, const uint8_t *key, const uint8_t *hkey, 
        int comp)
{
    scs_err_t rc;

    /* Silently truncate tid if longer than sizeof keyset->tid (64 bytes). */
    (void) snprintf(keyset->tid, sizeof keyset->tid, "%s", tid);

    /* Set the compression flag as requested.  In case zlib is not available 
     * on the platform, ignore user request and set to false. */
#ifdef HAVE_LIBZ
    keyset->comp = comp;
#else
    keyset->comp = 0;
#endif  /* HAVE_LIBZ */

    /* Setup keyset and cipherset. */
    switch ((keyset->cipherset = cipherset))
    {
        case AES_128_CBC_HMAC_SHA1:
            keyset->key_sz = keyset->block_sz = 16;
            keyset->hkey_sz = 20;
            break;
        default:
            rc = SCS_ERR_WRONG_CIPHERSET;
            goto err;
    }

    /* Internalise keying material. */
    memcpy(keyset->key, key, keyset->key_sz);
    memcpy(keyset->hkey, hkey, keyset->hkey_sz);

    return SCS_OK;
err:
    return rc;
}

static int decode_atoms (scs_t *scs, const char *b64_data, 
        const char *b64_atime, const char *b64_iv, const char *b64_tag,
        const char *b64_tid)
{
    size_t i;
    enum { NUM_ATOMS = 5 };
    struct {
        const char *id;
        char *raw, *enc;
        size_t *raw_sz, enc_sz;
    } A[NUM_ATOMS];

    /* TODO */

    for (i = 0; i < NUM_ATOMS; ++i)
    {
        if (!base64_decode(A[i].enc, A[i].enc_sz, A[i].raw, A[i].raw_sz))
        {
            scs_set_error(scs, SCS_ERR_DECODE, "%s decoding failed", A[i].id);
            return -1;
        }
    }

    return 0;
}

static scs_keyset_t *retr_keyset (scs_t *scs, const char *tid)
{
    char raw_tid[SCS_TID_MAX];
    size_t raw_tid_len = sizeof raw_tid - 1;

    /* Make sure we have room for the terminating NUL char. */
    if (!base64_decode(tid, strlen(tid), raw_tid, &raw_tid_len))
    {
        scs_set_error(scs, SCS_ERR_DECODE, "Base-64 decoding of tid failed");
        return NULL;
    }

    raw_tid[raw_tid_len] = '\0';

    if (scs->cur_keyset.active && !strcmp(raw_tid, scs->cur_keyset.tid))
        return &scs->cur_keyset;

    if (scs->prev_keyset.active && !strcmp(raw_tid, scs->prev_keyset.tid))
        return &scs->prev_keyset;

    scs_set_error(scs, SCS_ERR_WRONG_TID, "tid %s not found", raw_tid);
    return NULL;
}

static int tags_match (scs_t *scs, const char *tag)
{
    if (!strcmp(scs->b64_tag, tag))
        return 0;

    scs_set_error(scs, SCS_ERR_TAG_MISMATCH, 
            "\'%s\' != \'%s\'", scs->b64_tag, tag);

    return -1;
}

static int atime_ok (scs_t *scs)
{
    time_t now;
    char ebuf[128];
    time_t delta;

    if ((now = time(NULL)) == (time_t) -1)
    {
        (void) strerror_r(errno, ebuf, sizeof ebuf);
        scs_set_error(scs, SCS_ERR_OS, "time(3) failed: %s", ebuf);
        return -1;
    }

    if ((delta = (now - scs->atime)) <= scs->max_session_age)
        return 0;

    scs_set_error(scs, SCS_ERR_SESSION_EXPIRED, 
            "session expired %"PRIdMAX" seconds ago", 
            (intmax_t) (delta - scs->max_session_age));

    return -1;
}

static int decode_state (scs_t *scs, scs_keyset_t *ks, uint8_t **pstate, 
        size_t *pstate_sz)
{
    return 0;
}

static int optional_uncompress (scs_t *scs)
{
    return 0;
}

static void debug_print_cookies (scs_t *scs)
{
    printf("SCS_ATIME = %s\n", scs->b64_atime);
    printf("SCS_AUTHTAG = %s\n", scs->b64_tag);
    printf("SCS_DATA = %s\n", scs->b64_data);
    printf("SCS_TID = %s\n", scs->b64_tid);
    printf("SCS_IV = %s\n", scs->b64_iv);
}
