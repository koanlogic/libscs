/*
 * (c) KoanLogic Srl - 2011
 */ 

#include <assert.h>
#include <stdio.h>
#include <stdlib.h> 
#include <time.h>
#include <string.h>
#include <inttypes.h>
#include "scs.h"
#include "base64.h"
#include "conf.h"
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
    int (*enc) (scs_t *scs, uint8_t *in, size_t in_sz, uint8_t *out);
    int (*tag) (scs_t *scs, const char *);
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
static int comp (const char *in, uint8_t *out, size_t *pout_sz);
static int pad (size_t block_sz, uint8_t *b, size_t *sz, size_t capacity);
static int get_atime (scs_t *scs);
static int alloc_data (scs_t *scs);
static int prep_tag (scs_t *scs, char **pauth_blob);
static void print_buf (const char *label, const uint8_t *b, size_t b_sz);
static void print_cookies (scs_t *scs);

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
    if ((s = malloc(sizeof *s)) == NULL)
        return SCS_ERR_MEM;

    /* Initialize current keyset. */
    rc = init_keyset(&s->cur_keyset, tid, cipherset, key, hkey, comp);
    if (rc != SCS_OK)
        goto err;

    s->max_session_age = max_session_age;

    /* Initialize the .data* fields explicitly, so that free(3) won't die on 
     * scs_reset_atoms(). */
    s->data = NULL;
    s->b64_data = NULL;

    s->cur_keyset.avail = 1;
    s->prev_keyset.avail = 0;

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

/**
 *  \brief  Prepare SCS PDU atoms to save the supplied \p state string 
 *          to remote UA.
 */ 
int scs_save (scs_t *scs, const char *state)
{
    scs_err_t rc;
    size_t state_sz;
    scs_keyset_t *ks;
    char *auth_blob = NULL;

    /* TODO check preconditions. */

    /* Cleanup protocol atoms from a previous run. */
    scs_reset_atoms(scs);

    /* Working keyset is the current. */
    ks = &scs->cur_keyset;

    /* Randomly generate the block cipher IV. */
    if (D.gen_iv(scs))
        return SCS_ERR_CRYPTO;

    /* Get 'atime' from the computer's clock. */
    if ((rc = get_atime(scs)) != SCS_OK)
        return rc;

    /* Make room for the working buf, taking care for IV, padding and potential
     * exansion due to compress overhead. */
    state_sz = strlen(state);
    scs->data_capacity = state_sz + (2 * ks->block_sz) + 1024;
    if ((rc = alloc_data(scs)) != SCS_OK)
        goto err;

    /* Optionally compress the supplied state string before encryption. */
    if (!ks->comp)
    {
        scs->data_sz = state_sz;
        memcpy(scs->data, (uint8_t *) state, scs->data_sz);
    }
    else 
    {
        scs->data_sz = scs->data_capacity;
        if ((rc = comp(state, scs->data, &scs->data_sz)) != SCS_OK)
            goto err;
    }

    /* Pad data to please the block encyption cipher, if needed. */
    rc = pad(ks->block_sz, scs->data, &scs->data_sz, scs->data_capacity);
    if (rc != SCS_OK)
        goto err;

    //print_buf("[PADDED]", scs->data, scs->data_sz);

    /* Encrypt. */
    if (D.enc(scs, scs->data, scs->data_sz, scs->data))
    {
        rc = SCS_ERR_CRYPTO;
        goto err;
    }

    /* Prepare authentication data for tagging. */
    if ((rc = prep_tag(scs, &auth_blob)) != SCS_OK)
        goto err;

    /* Create auth tag. */
    if (D.tag(scs, auth_blob))
    {
        rc = SCS_ERR_CRYPTO;
        goto err;
    }

    /* Base-64 encode it. */
    base64_encode((const char *) scs->tag, scs->tag_sz, 
            scs->b64_tag, sizeof scs->b64_tag);

    print_cookies(scs);

    free(auth_blob), auth_blob = NULL;

    return SCS_OK;
err:
    free(auth_blob);
    scs_reset_atoms(scs);   /* Cleanup garbage. */
    return rc;
}

/**
 *  \brief  Reset protocol atoms values.
 */ 
void scs_reset_atoms (scs_t *scs)
{
    if (scs == NULL)
        return;

    free(scs->data), scs->data = NULL;
    free(scs->b64_data), scs->b64_data = NULL;
    scs->data_sz = scs->data_capacity = 0;
    scs->tag_sz = 0;
    scs->atime = (time_t) -1;

    return;
}

int scs_restore (scs_t *scs)
{
    /* TODO */
    return 0;
}

static int comp (const char *in, uint8_t *out, size_t *pout_sz)
{
#ifdef HAVE_LIBZ
    int ret;
    z_stream zstr;

    zstr.zalloc = Z_NULL;
    zstr.zfree = Z_NULL;
    zstr.opaque = Z_NULL;

    if (deflateInit(&zstr, Z_DEFAULT_COMPRESSION) != Z_OK)
        return SCS_ERR_COMPRESSION;

    zstr.next_in = (Byte *) in;
    zstr.avail_in = strlen(in);

    zstr.next_out = out;
    zstr.avail_out = *pout_sz;

    /* We can't overflow the output buffer as long as '*pout_sz' is the
     * real size of 'out'. */
    ret = deflate(&zstr, Z_FINISH);
    if (ret != Z_STREAM_END)
        goto err;

    *pout_sz = zstr.total_out;

    deflateEnd(&zstr);

    return SCS_OK;
err:
    printf("%s\n", zError(ret));
    deflateEnd(&zstr);
    return SCS_ERR_COMPRESSION;
#else
    assert(!"I'm not supposed to get there...");
#endif  /* HAVE_LIBZ */
}

static int pad (size_t block_sz, uint8_t *b, size_t *sz, size_t capacity)
{
    size_t pad_len = block_sz - (*sz % block_sz);

    /* This padding method is well defined if and only if k (i.e. pad_len) 
     * is less than 256. */
    assert(pad_len < 256);  

    if (*sz + pad_len > capacity)
        return SCS_ERR_MEM;

    if (pad_len)
    {
        /* If the length of (compressed) state is not a multiple of the 
         * block size, its value will be filled with padding bytes of equal 
         * value as the pad length -- see Section 6.3 of [CMS]. */
        memset(b + *sz, pad_len, pad_len);
        *sz += pad_len;
    }

    return SCS_OK;
}

static void print_buf (const char *label, const uint8_t *b, size_t b_sz)
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

static int prep_tag (scs_t *scs, char **pauth_blob)
{
    size_t i, tot_sz = 0;
    char *auth_blob = NULL, *p;
    scs_keyset_t *ks = &scs->cur_keyset;
    enum { NUM_PIECES = 4 };
    struct {
        char *raw, *encoded;
        size_t raw_sz, encoded_sz;
    } A[NUM_PIECES] = {
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
            BASE64_LENGTH(strlen(scs->s_atime))
        },
        {
            ks->tid,
            scs->b64_tid,
            strlen(ks->tid),
            BASE64_LENGTH(strlen(ks->tid))
        },
        {
            (char *) scs->iv,
            scs->b64_iv,
            ks->block_sz,
            BASE64_LENGTH(ks->block_sz)
        }
    };

    /* 
     * Compute total length of the authentication blob and make room for it. 
     * Add 3 extra chars for fields separators and 1 more to please the base64
     * encoder.
     */
    for (i = 0; i < NUM_PIECES; ++i)
        tot_sz += A[i].encoded_sz;
    tot_sz += (3 + 1);

    if ((auth_blob = malloc(tot_sz)) == NULL)
        return SCS_ERR_MEM;

    /* Handle each field's encoding and concatenation. */
    for (p = auth_blob, i = 0; i < NUM_PIECES; ++i)
    {
        base64_encode(A[i].raw, A[i].raw_sz, p, tot_sz);

        /* Make a copy of the encoded atom. */
        strcpy(A[i].encoded, p);

        tot_sz -= A[i].encoded_sz;
        p += A[i].encoded_sz;

        /* Add the '|' separator after each field but the last one. */
        if (i != NUM_PIECES - 1)
        {
            *p++ = '|';
            --tot_sz;
        }
    }

    *pauth_blob = auth_blob;

    return 0;
}

static int get_atime (scs_t *scs)
{
    if ((scs->atime = time(NULL)) == (time_t) -1)
        return SCS_ERR_OS;

    /* Get string representation of atime which will be used later on when 
     * creating the authentication tag. */
    (void) snprintf(scs->s_atime, sizeof scs->s_atime, 
            "%"PRIdMAX, (intmax_t) scs->atime);

    return SCS_OK;
}

static int alloc_data (scs_t *scs)
{
    size_t b64_data_sz = BASE64_LENGTH(scs->data_capacity) + 1;

    if ((scs->data = malloc(scs->data_capacity)) == NULL || 
            (scs->b64_data = malloc(b64_data_sz)) == NULL)
        return SCS_ERR_MEM;

    return SCS_OK;
}

static void print_cookies (scs_t *scs)
{
    printf("SCS_ATIME = %s\n", scs->b64_atime);
    printf("SCS_AUTHTAG = %s\n", scs->b64_tag);
    printf("SCS_DATA = %s\n", scs->b64_data);
    printf("SCS_TID = %s\n", scs->b64_tid);
    printf("SCS_IV = %s\n", scs->b64_iv);
}
