/* (c) KoanLogic Srl - 2011 */ 

#include <sys/param.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h> 
#include <time.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>

#include "missing.h"
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

#ifdef HAVE_LIBZ
  int have_libz = 1;
#else
  int have_libz = 0;
#endif  /* HAVE_LIBZ */

static struct
{
    int (*init) (void);
    int (*rand) (scs_t *ctx, uint8_t *b, size_t b_sz);
    int (*enc) (scs_t *ctx);
    int (*dec) (scs_t *ctx, scs_keyset_t *ks);
    int (*tag) (scs_t *ctx, scs_keyset_t *ks);
    void (*term) (void);
} D = {
#ifdef USE_CYASSL
    cyassl_init,
    cyassl_rand,
    cyassl_enc,
    cyassl_dec,
    cyassl_tag,
    cyassl_term
#elif defined (USE_OPENSSL)
    openssl_init,
    openssl_rand,
    openssl_enc,
    openssl_dec,
    openssl_tag,
    openssl_term
#endif
};

static int init_keyset (scs_t *ctx, scs_keyset_t *ks, const char *tid, int comp,
        scs_cipherset_t cipherset, const uint8_t *key, const uint8_t *hkey);
static int new_key (uint8_t *dst, const uint8_t *src, size_t sz);
static int set_tid (scs_t *ctx, scs_keyset_t *ks, const char *tid);
static void reset_atoms (scs_atoms_t *atoms);
static int gen_tid (scs_t *ctx, char tid[SCS_TID_MAX], size_t tid_len);
static int what_time_is_it (scs_t *ctx, time_t *pnow);

/* Encode support. */
static int get_random_iv (scs_t *ctx);
static int get_atime (scs_t *ctx);
static int optional_deflate (scs_t *ctx, const uint8_t *st, size_t st_sz);
static int do_deflate (scs_t *ctx, const uint8_t *state, size_t state_sz);
static int encrypt_state (scs_t *ctx);
static int add_pad (scs_t *ctx);
static int create_tag (scs_t *ctx, scs_keyset_t *ks, int skip_encoding);
static const char *do_cookie (scs_t *ctx, char cookie[SCS_COOKIE_MAX]);

/* Decode support. */
static scs_keyset_t *retr_keyset (scs_t *ctx);
static int attach_atoms (scs_t *ctx, const char *b64_data, 
        const char *b64_atime, const char *b64_tid, const char *b64_iv, 
        const char *b64_tag);
static int decode_atoms (scs_t *ctx, scs_keyset_t *ks);
static int tags_match (scs_t *ctx, const char *tag);
static int atime_ok (scs_t *ctx);
static int optional_inflate (scs_t *ctx, scs_keyset_t *ks);
static int decrypt_state (scs_t *ctx, scs_keyset_t *ks);
static int remove_pad (scs_t *ctx);
static int do_inflate (scs_t *ctx);
static int split_cookie (scs_t *ctx, const char *cookie, 
        char tag[BASE64_LENGTH(SCS_TAG_MAX) + 1]);
static void *verify (scs_t *ctx, const char *tag, size_t *pstate_sz);

/* Auto refresh support. */
static int check_update_keyset (scs_t *ctx);
static int update_last_refresh (scs_t *ctx, time_t now);

/**
 *  \defgroup scs SCS
 *  \{
 *      TODO
 *
 *      \section init   Initialization
 *      TODO
 *
 *      \section encode Encoding
 *      TODO
 *
 *      \section decode Decoding
 *      TODO
 *
 *      \section refresh    Automatic Refreshing of Keying Material
 *      TODO
 */

/**
 *  \brief  Encode plain cookie-value to an SCS cookie-value.
 *
 *  Given the supplied \p state blob return the SCS cookie string
 *  into the \p cookie char buffer.  The \p cookie must be at least
 *  SCS_COOKIE_MAX bytes long and pre-allocated by the caller.
 *  When an error occurs \c NULL is returned and the supplied \p ctx 
 *  can be inspected for failure cause -- \sa scs_err function.
 *
 *  \param  ctx         TODO
 *  \param  state       TODO
 *  \param  state_sz    TODO
 *  \param  cookie      TODO
 *
 *  \return TODO
 */
const char *scs_encode (scs_t *ctx, const uint8_t *state, size_t state_sz,
        char cookie[SCS_COOKIE_MAX])
{
    scs_atoms_t *ats = &ctx->atoms;
    scs_keyset_t *ks = &ctx->cur_keyset;
    int skip_atoms_encoding = 1;

    /* Before doing anything useful, check if keyset needs to be updated. 
     * All crypto ops must be carried against a "fresh" -- as defined by the
     * current policy -- keyset. */
    if (check_update_keyset(ctx))
        return NULL;

    reset_atoms(ats);

    /*  iv = rand()
     *  atime = now()
     *  Trans = (compression enabled) ? Deflate : Id
     *  state' = Trans(state)
     *  data = E_k(state')
     *  tag = HMAC_h(b64(data) || "|" || b64(atime) || "|" ||
     *               b64(tid)  || "|" || b64(iv))
     *  scs_cookie = 
     *      "b64(data) '|' b64(atime) '|' b64(tid) '|' b64(iv) '|' b64(tag)" */
    if (get_random_iv(ctx) 
            || get_atime(ctx) 
            || optional_deflate(ctx, state, state_sz) 
            || encrypt_state(ctx) 
            || create_tag(ctx, ks, !skip_atoms_encoding))
    {
        reset_atoms(ats);   /* Remove any garbage. */
        return NULL;
    }

    /* Given all the atoms, create the encoded cookie value. */
    return do_cookie(ctx, cookie);
}

/** \brief  Decode the supplied SCS \p cookie string.  
 *          If verification is successful, the embedded state blob is returned
 *          to the caller whose length is found at \p *pstate_sz. */
void *scs_decode (scs_t *ctx, const char *cookie, size_t *pstate_sz)
{
    char tag[BASE64_LENGTH(SCS_TAG_MAX) + 1];

    /* Check current keyset status. */
    if (check_update_keyset(ctx))
        return NULL;

    /* Cleanup the context. */
    reset_atoms(&ctx->atoms);

    /* Get SCS atoms. */
    if (split_cookie(ctx, cookie, tag))
        return NULL;

    /* Handle the PDU validation process. */
    return verify(ctx, tag, pstate_sz); 
}

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
        const uint8_t *hkey, int comp, time_t session_max_age, scs_t **ps)
{
    scs_err_t rc;
    scs_t *s = NULL;

    /* Initialize the crypto toolkit. */
    if (D.init() == -1)
        return SCS_ERR_CRYPTO;

    /* Make room for the SCS context structure. */
    if ((s = malloc(sizeof *s)) == NULL)
        return SCS_ERR_MEM;

    /* Initialize current keyset. */
    if ((rc = init_keyset(s, &s->cur_keyset, tid, comp, cipherset, key, hkey)))
        goto err;

    /* Initialize last refresh timestamp. */
    if (what_time_is_it(s, &s->last_refresh))
    {
        rc = SCS_ERR_OS;
        goto err;
    }

    s->refresh_mode = SCS_REFRESH_MANUAL;

    /* Upper bound session lifetime. */
    s->session_max_age = session_max_age;

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
err:
    if (s)
        free(s);
    return rc;
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

/** \brief  Return last error string. */
const char *scs_err (scs_t *ctx) 
{
    return ctx->estr;
}

/**
 *  Refresh current keyset with the supplied keying material.
 */ 
int scs_refresh_keyset (scs_t *ctx, const char *new_tid, const uint8_t *key, 
        const uint8_t *hkey)
{
    time_t now;
    scs_keyset_t *ks = &ctx->cur_keyset;

    scs_keyset_t *cur = &ctx->cur_keyset, *prev = &ctx->prev_keyset, tmp;

    tmp = *prev;
    *prev = *cur;

    /* Get current timestamp. */
    if (what_time_is_it(ctx, &now))
        return -1;

    /* Create new keying material. */
    if (new_key(ks->key, key, ks->key_sz)
            || new_key(ks->hkey, hkey, ks->hkey_sz))
    {
        scs_set_error(ctx, SCS_ERR_CRYPTO, "keyset update failed.");
        goto recover;
    }

    /* Set new tid name. */
    if (set_tid(ctx, cur, new_tid))
        return -1;

    return 0;

recover:
    *cur = *prev;
    *prev = tmp;

    return -1;
}

/**
 *  \brief  Set auto-refresh policy parameters.
 */ 
int scs_auto_refresh_setup (scs_t *ctx, time_t refresh_freq, time_t expiry)
{
    ctx->refresh_mode = SCS_REFRESH_AUTO;

    ctx->refresh_freq = MAX(refresh_freq, ctx->session_max_age);
    ctx->expiry = MIN(expiry, ctx->session_max_age);

    return 0; 
}

/**
 *  \}
 */


/*
 * Create the SCS cookie string given the computed atoms:
 *      scs_cookie = "b64(data)'|'b64(atime)'|'b64(tid)'|'b64(iv)'|'b64(tag)"
 */
static const char *do_cookie (scs_t *ctx, char cookie[SCS_COOKIE_MAX])
{
    int rc;
    scs_atoms_t *ats = &ctx->atoms;

    rc = snprintf(cookie, SCS_COOKIE_MAX, "%s|%s|%s|%s|%s", ats->b64_data, 
            ats->b64_atime, ats->b64_tid, ats->b64_iv, ats->b64_tag);

    if (rc >= SCS_COOKIE_MAX)
    {
        scs_set_error(ctx, SCS_ERR_IMPL, "SCS_COOKIE_MAX limit hit");
        return NULL;
    }

    return cookie;
}

/* Split SCS atoms.  Also save a copy of the base-64 encoded tag since 
 * create_tag() will overwrite ats->b64_tag with the newly computed one, 
 * and we still need it in tags_match() for comparison/validation. */
static int split_cookie (scs_t *ctx, const char *cookie, 
        char tag[BASE64_LENGTH(SCS_TAG_MAX) + 1])
{
    size_t n;
    char cp[SCS_COOKIE_MAX] = { '\0' }, *pcp = &cp[0];
    enum { DATA = 0, ATIME, TID, IV, TAG, NUM_ATOMS };
    char *atoms[NUM_ATOMS + 1], **ap;

    /* Make a copy that we can freely clobber with strsep(). */
    if (strlcpy(cp, cookie, sizeof cp) >= sizeof cp)
    {
        scs_set_error(ctx, SCS_ERR_FRAMING, "SCS_COOKIE_MAX exceeded");
        return -1;
    }

    /* Put the expected 5 atoms on corresponding atoms[] slots, also doing
     * trivial integrity check (i.e. correct number and non-empty atoms.) */
    for (n = 0, ap = atoms; (*ap = strsep(&pcp, "|")) != NULL; n++)
    {
        if (**ap == '\0' && n < NUM_ATOMS)
        {
            /* empty field */
            scs_set_error(ctx, SCS_ERR_FRAMING, "field %zu is empty", n);
            return -1;
        }

        if (++ap > &atoms[NUM_ATOMS])
        {
            scs_set_error(ctx, SCS_ERR_FRAMING, "too much atoms");
            return -1;
        }
    }

    if (n != NUM_ATOMS)
    {
        scs_set_error(ctx, SCS_ERR_FRAMING, "got %zu atom(s), need 5", n);
        return -1;
    }

    /* Make a copy of the supplied authtag that can be compared with the
     * re-computed authtag. */
    (void) strlcpy(tag, atoms[TAG], BASE64_LENGTH(SCS_TAG_MAX) + 1);

    /* Attach atoms to context. */
    return attach_atoms(ctx, atoms[DATA], atoms[ATIME], atoms[TID], 
                        atoms[IV], atoms[TAG]);
}

/* Internal version of scs_decode(). */
static void *verify (scs_t *ctx, const char *tag, size_t *pstate_sz)
{
    scs_keyset_t *ks;
    scs_atoms_t *ats = &ctx->atoms;
    int skip_atoms_encoding = 1;

    /* 1.  If (tid is available)
     * 2.      data' = d($SCS_DATA)
     *         atime' = d($SCS_ATIME)
     *         tid' = d($SCS_TID)
     *         iv' = d($SCS_IV)
     *         tag' = d($SCS_AUTHTAG)
     * 3.     tag = HMAC(<data'>||<atime'>||<tid'>||<iv'>)
     * 4.     If (tag == tag' && NOW - atime' <= session_max_age)
     * 5.         state = Uncomp(Dec(data'))
     * 6.     Else discard PDU
     * 7.  Else discard PDU        */
    if ((ks = retr_keyset(ctx)) == NULL 
            || decode_atoms(ctx, ks)
            || create_tag(ctx, ks, skip_atoms_encoding)
            || tags_match(ctx, tag)
            || atime_ok(ctx)
            || decrypt_state(ctx, ks)
            || optional_inflate(ctx, ks))
    {
        reset_atoms(ats);
        return NULL;
    }

    *pstate_sz = ats->data_sz;

    return ats->data;
}

/* Let the crypto toolkit handle PR generation of the block cipher IV.
 * The crypto driver is in charge of error reporting through scs_set_error(). */
static int get_random_iv (scs_t *ctx)
{
    scs_atoms_t *ats = &ctx->atoms;
    scs_keyset_t *ks = &ctx->cur_keyset;

    return D.rand(ctx, ats->iv, ks->block_sz);
}

/* Retrieve current time in seconds since UNIX epoch. */
static int get_atime (scs_t *ctx)
{
    time_t atime;
    scs_atoms_t *ats = &ctx->atoms;

    /* Get current timestamp. */
    if (what_time_is_it(ctx, &atime))
        return -1;

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

static int optional_deflate (scs_t *ctx, const uint8_t *state, size_t state_sz)
{
    scs_atoms_t *ats = &ctx->atoms;
    scs_keyset_t *ks = &ctx->cur_keyset;

    /* Assume we have already passed through reset_atoms(). */
    assert(ats->data_sz == sizeof ats->data);

    if (!ks->comp)
    {
        ats->data_sz = state_sz;
        memcpy(ats->data, (uint8_t *) state, ats->data_sz);
        return 0;
    }

    return do_deflate(ctx, state, state_sz);
}

/* Pad data to please the block encyption cipher, if needed, then encrypt. */
static int encrypt_state (scs_t *ctx)
{
    return (add_pad(ctx) || D.enc(ctx));
}

static int create_tag (scs_t *ctx, scs_keyset_t *ks, int skip_encoding)
{
    size_t i;
    scs_atoms_t *ats = &ctx->atoms;
    enum { NUM_ATOMS = 4 };
    struct {
        const char *id;
        uint8_t *raw; 
        char *enc;
        size_t raw_sz, enc_sz;
    } A[NUM_ATOMS] = {
        { 
            "SCS DATA",
            ats->data,
            ats->b64_data,
            ats->data_sz,
            BASE64_LENGTH(ats->data_sz)
        },
        { 
            "SCS ATIME",
            (uint8_t *) ats->atime,
            ats->b64_atime,
            strlen(ats->atime),
            sizeof(ats->b64_atime)
        },
        {
            "SCS TID",
            (uint8_t *) ks->tid,
            ats->b64_tid,
            strlen(ks->tid),
            sizeof(ats->b64_tid)
        },
        {
            "SCS IV",
            ats->iv,
            ats->b64_iv,
            ks->block_sz,
            BASE64_LENGTH(ks->block_sz)
        }
    };    
    
    /* If requested, create Base-64 encoded versions of atoms. */
    if (!skip_encoding)
    {
        for (i = 0; i < NUM_ATOMS; ++i)
        {
            if (base64_encode(A[i].raw, A[i].raw_sz, A[i].enc, A[i].enc_sz))
            {
                scs_set_error(ctx, SCS_ERR_ENCODE, "%s encode failed", A[i].id);
                return -1;
            }
        }
    }

    /* Create auth tag. */
    if (D.tag(ctx, ks))
        return -1;

    /* Base-64 encode the auth tag. */
    if (base64_encode(ats->tag, ats->tag_sz, ats->b64_tag, sizeof ats->b64_tag))
    {
        scs_set_error(ctx, SCS_ERR_ENCODE, "tag encode failed", A[i].id);
        return -1;
    }

    return 0;
}

/* Reset protocol atoms values. */
static void reset_atoms (scs_atoms_t *ats)
{
    memset(ats, 0, sizeof *ats);

    /* Set to the maximum available. */
    ats->data_sz = sizeof(ats->data);
    ats->tag_sz = sizeof(ats->tag);

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
static int do_deflate (scs_t *ctx, const uint8_t *state, size_t state_sz)
{
#ifdef HAVE_LIBZ
    int ret;
    z_stream zstr;
    scs_atoms_t *ats = &ctx->atoms;

    zstr.zalloc = Z_NULL;
    zstr.zfree = Z_NULL;
    zstr.opaque = Z_NULL;

    if ((ret = deflateInit(&zstr, Z_DEFAULT_COMPRESSION)) != Z_OK)
        goto err;

    zstr.next_in = (Bytef *) state;
    zstr.avail_in = state_sz;

    zstr.next_out = ats->data;
    zstr.avail_out = ats->data_sz;

    /* We can't overflow the output buffer as long as '*pout_sz' is the
     * real size of 'out'. */
    if ((ret = deflate(&zstr, Z_FINISH)) != Z_STREAM_END)
        goto err;

    ats->data_sz = zstr.total_out;

    deflateEnd(&zstr);

    return 0;
err:
    scs_set_error(ctx, SCS_ERR_COMPRESSION, "zlib error: %s", zError(ret));
    deflateEnd(&zstr);
    return -1;
#else
    assert(!"I'm not supposed to get there without zlib...");
#endif  /* HAVE_LIBZ */
}

static int add_pad (scs_t *ctx)
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

    memset(ats->data + *sz, pad_len, pad_len);
    *sz += pad_len;

    return 0;
}

static int set_tid (scs_t *ctx, scs_keyset_t *ks, const char *tid)
{
    if (tid == SCS_TID_AUTO)
        return gen_tid(ctx, ks->tid, SCS_TID_AUTO_LEN);

    return (strlcpy(ks->tid, tid, sizeof ks->tid) >= sizeof ks->tid) ? -1 : 0;
}

static int init_keyset (scs_t *ctx, scs_keyset_t *ks, const char *tid, int comp,
        scs_cipherset_t cipherset, const uint8_t *key, const uint8_t *hkey)
{
    if (set_tid(ctx, ks, tid))
        return SCS_ERR_BAD_TID;

    /* Set the compression flag as requested.  In case zlib is not available 
     * on the platform, ignore user request and set to false. */
    ks->comp = have_libz ? comp : 0;

    /* Setup keyset and cipherset. */
    switch ((ks->cipherset = cipherset))
    {
        case AES_128_CBC_HMAC_SHA1:
            ks->key_sz = ks->block_sz = 16;
            ks->hkey_sz = 20;
            break;
        default:
            return SCS_ERR_WRONG_CIPHERSET;
    }

    /* Create or attach new HMAC and cipher keys. */
    if (new_key(ks->key, key, ks->key_sz)
            || new_key(ks->hkey, hkey, ks->hkey_sz))
        return SCS_ERR_CRYPTO;

    return SCS_OK;
}

static scs_keyset_t *retr_keyset (scs_t *ctx)
{
    char raw_tid[SCS_TID_MAX];
    scs_atoms_t *ats = &ctx->atoms;
    size_t raw_tid_len = sizeof raw_tid - 1;

    /* Make sure we have room for the terminating NUL char. */
    if (base64_decode(ats->b64_tid, strlen(ats->b64_tid), 
                (uint8_t *) raw_tid, &raw_tid_len))
    {
        scs_set_error(ctx, SCS_ERR_DECODE, "Base-64 decoding of tid failed");
        return NULL;
    }

    raw_tid[raw_tid_len] = '\0';

    /* Try active keyset first. */
    if (ctx->cur_keyset.active 
            && !strcmp(raw_tid, ctx->cur_keyset.tid))
        return &ctx->cur_keyset;

    /* Then backup. */
    if (ctx->prev_keyset.active 
            && !strcmp(raw_tid, ctx->prev_keyset.tid))
        return &ctx->prev_keyset;

    /* Not found. */
    scs_set_error(ctx, SCS_ERR_WRONG_TID, "tid \'%s\' not found", raw_tid);
    return NULL;
}

/* Possible truncation will be detected in some later processing stage. */
static int attach_atoms (scs_t *ctx, const char *b64_data, 
        const char *b64_atime, const char *b64_tid, const char *b64_iv, 
        const char *b64_tag)
{
    size_t i;
    scs_atoms_t *ats = &ctx->atoms;
    enum { NUM_ATOMS = 5 };
    struct {
        const char *cookie, *b64;
        char *cp;
        size_t max_sz, b64_sz; 
    } A[NUM_ATOMS] = {
        { 
            "SCS DATA",
            b64_data,
            ats->b64_data,
            sizeof(ats->b64_data),
            strlen(b64_data) + 1
        },
        {
            "SCS ATIME",
            b64_atime,
            ats->b64_atime,
            sizeof(ats->b64_atime),
            strlen(b64_atime) + 1
        },
        {
            "SCS TID",
            b64_tid,
            ats->b64_tid,
            sizeof(ats->b64_tid),
            strlen(b64_tid) + 1
        },
        {
            "SCS IV",
            b64_iv,
            ats->b64_iv,
            sizeof(ats->b64_iv),
            strlen(b64_iv) + 1
        },
        {
            "SCS AUTHTAG",
            b64_tag,
            ats->b64_tag,
            sizeof(ats->b64_tag),
            strlen(b64_tag) + 1
        }
    };

    for (i = 0; i < NUM_ATOMS; ++i)
    {
        if (strlcpy(A[i].cp, A[i].b64, A[i].max_sz) >= A[i].max_sz)
        {
            scs_set_error(ctx, SCS_ERR_IMPL, "%s too long: %zu vs %zu", 
                    A[i].cookie, A[i].b64_sz, A[i].max_sz);
            return -1;
        }
    }

    return 0;
}

/* Note that tid has been already decoded in order to identify the running
 * keyset inside retr_keyset().  Its value is found in the selected keyset. */
static int decode_atoms (scs_t *ctx, scs_keyset_t *ks)
{
    scs_atoms_t *ats = &ctx->atoms;
    size_t i, atime_sz = sizeof(ats->atime), iv_sz = ks->block_sz;
    enum { NUM_ATOMS = 4 };
    struct {
        const char *id;
        uint8_t *raw;
        size_t *raw_sz;
        const char *enc;
        size_t enc_sz;
    } A[NUM_ATOMS] = {
        {
            "SCS DATA",
            ats->data,
            &ats->data_sz,      /* Initially set to data_capacity. */
            ats->b64_data,
            strlen(ats->b64_data)
        },
        {
            "SCS ATIME",
            (uint8_t *) ats->atime,
            &atime_sz,
            ats->b64_atime,
            strlen(ats->b64_atime)
        },
        {
            "SCS IV",
            ats->iv,
            &iv_sz,
            ats->b64_iv,
            strlen(ats->b64_iv)
        },
        {
            "SCS AUTHTAG",
            ats->tag,
            &ats->tag_sz,
            ats->b64_tag,
            strlen(ats->b64_tag)
        }
    };

    for (i = 0; i < NUM_ATOMS; ++i)
    {
        if (base64_decode(A[i].enc, A[i].enc_sz, A[i].raw, A[i].raw_sz))
        {
            scs_set_error(ctx, SCS_ERR_DECODE, "%s decoding failed", A[i].id);
            return -1;
        }
    }

    /* Terminate atime string. */
    ats->atime[atime_sz] = '\0';

    return 0;
}

static int tags_match (scs_t *ctx, const char *tag)
{
    scs_atoms_t *ats = &ctx->atoms;

    if (!strcmp(ats->b64_tag, tag))
        return 0;

    scs_set_error(ctx, SCS_ERR_TAG_MISMATCH, 
            "tag mismatch: %s != %s", ats->b64_tag, tag);

    return -1;
}

static int atime_ok (scs_t *ctx)
{
    time_t now, atime, delta;
    scs_atoms_t *ats = &ctx->atoms;

    /* Get current timestamp. */
    if (what_time_is_it(ctx, &now))
        return -1;

    /* Get time_t representation of atime (XXX do it better). */
    atime = (time_t) atoi(ats->atime);

    if ((delta = (now - atime)) <= ctx->session_max_age)
        return 0;

    scs_set_error(ctx, SCS_ERR_SESSION_EXPIRED, 
            "session expired %"PRIdMAX" seconds ago", 
            (intmax_t) (delta - ctx->session_max_age));

    return -1;
}

static int decrypt_state (scs_t *ctx, scs_keyset_t *ks)
{
    /* Decrypt and remove padding, if any. */
    return (D.dec(ctx, ks) || remove_pad(ctx));
}

static int remove_pad (scs_t *ctx)
{
    scs_atoms_t *ats = &ctx->atoms;
    size_t i, sz = ats->data_sz;
    uint8_t *data = ats->data, *padlen = data + sz - 1;

    for (i = sz - 1; i >= sz - *padlen; --i)
    {
        if (data[i] != *padlen)
        {
            scs_set_error(ctx, SCS_ERR_BAD_PAD, "wrong padding byte: "
                    "expected %u, found %u", *padlen, data[i]);
            return -1;
        }

        ats->data_sz -= 1;
    }

    return 0;
}

static int optional_inflate (scs_t *ctx, scs_keyset_t *ks)
{
    return !ks->comp ? 0 : do_inflate(ctx);
}

static int do_inflate (scs_t *ctx)
{
#ifdef HAVE_LIBZ
    int ret;
    z_stream zstr;
    scs_atoms_t *ats = &ctx->atoms;

    zstr.zalloc = Z_NULL;
    zstr.zfree = Z_NULL;
    zstr.opaque = Z_NULL;

    if ((ret = inflateInit(&zstr)) != Z_OK)
        goto err;

    zstr.next_in = (Bytef *) ats->data;
    zstr.avail_in = ats->data_sz;

    /* TODO 
     * check if we have to use a temp buffer to avoid possible overwrite. */
    zstr.next_out = ats->data;
    zstr.avail_out = sizeof ats->data;

    if ((ret = inflate(&zstr, Z_FINISH)) != Z_STREAM_END)
        goto err;

    ats->data_sz = zstr.total_out;

    inflateEnd(&zstr);

    return 0;
err:
    scs_set_error(ctx, SCS_ERR_COMPRESSION, "zlib error: %s", zError(ret));
    inflateEnd(&zstr);
    return -1;
#else   /* !HAVE_LIBZ */
    assert(!"I'm not supposed to get there without zlib...");
#endif  /* HAVE_LIBZ */
}

static int gen_tid (scs_t *ctx, char tid[SCS_TID_MAX], size_t tid_len)
{
    char *dst = tid;
    uint8_t rand_block[SCS_TID_MAX], *src = &rand_block[0];
    size_t len = MIN(tid_len, SCS_TID_MAX);

    /* Fill rand_block with garbage. */
    if (D.rand(ctx, src, len))
        return -1;

    /* Convert random bytes to printable ASCII chars. */
    while (--len)
        *dst++ = (char) ((*src++ % 93) + 33);

    *dst = '\0';

    return 0;
}

static int check_update_keyset (scs_t *ctx)
{
    time_t now;

    if (ctx->refresh_mode != SCS_REFRESH_AUTO)
        return 0;

    if (what_time_is_it(ctx, &now))
        return -1;

    /* First of all we check if the expiry period of the previous keyset is 
     * elapsed, in which case the backup keyset is disposed.  Note that this 
     * could happen with a primary keyset still in good shape. */
    if (ctx->last_refresh + ctx->expiry < now)
        ctx->prev_keyset.active = 0;

    /* Then try and see if the primary keyset lifetime is expired... */
    if (now < ctx->last_refresh + ctx->refresh_freq)
        return 0;

    /* ...in which case the whole keyset is updated. */
    if (scs_refresh_keyset(ctx, SCS_TID_AUTO, SCS_KEY_AUTO, SCS_KEY_AUTO))
        return -1;

    /* Update last refresh timestamp. */
    (void) update_last_refresh(ctx, now);

    return 0;
}

static int what_time_is_it (scs_t *ctx, time_t *pnow)
{
    time_t now;
    char ebuf[128];

    if ((now = time(NULL)) == (time_t) -1)
    {
        (void) strerror_r(errno, ebuf, sizeof ebuf);
        scs_set_error(ctx, SCS_ERR_OS, "time(3) failed: %s", ebuf);
        return -1;
    }

    *pnow = now;

    return 0;
}

static int new_key (uint8_t *dst, const uint8_t *src, size_t sz)
{
    if (src == SCS_KEY_AUTO)
        return D.rand(NULL, dst, sz);

    memcpy(dst, src, sz);

    return 0;
}

static int update_last_refresh (scs_t *ctx, time_t now)
{
    /* Manual refresh: just do what we're told. */
    if (ctx->refresh_mode == SCS_REFRESH_MANUAL)
    {
        ctx->last_refresh = now;
        return 0;
    }

    /* Don't let further modulo operation be confused. */
    if (now == ctx->last_refresh)
        return 0;

    /* Automatic refresh update policy is to set .last_refresh timestamp
     * to the nearest (to now) multiple of .refresh_freq starting from previous
     * .last_refresh. */
    ctx->last_refresh = now - ((now - ctx->last_refresh) % ctx->refresh_freq);

    return 0;
}
