#include <sys/time.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/opensslv.h>

#include "openssl_drv.h"
#include "utils.h"

static int rng_init (void);

int openssl_init (void)
{
    /* Add just what is strictly needed. */
    EVP_add_cipher(EVP_aes_128_cbc());
    EVP_add_digest(EVP_sha1());

    if (rng_init() == -1)
        return -1;

    return 0;
}

int openssl_rand (scs_t *ctx, uint8_t *b, size_t b_sz)
{
    if (!RAND_bytes(b, b_sz))
    {
        scs_set_error(ctx, SCS_ERR_CRYPTO, "openssl error: %s",
                ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    return 0;
}

int openssl_enc (scs_t *ctx)
{
    EVP_CIPHER_CTX c;
    int tmp_sz, sz;
    scs_atoms_t *ats = &ctx->atoms;
    scs_keyset_t *ks = &ctx->cur_keyset;

    if (ks->cipherset != AES_128_CBC_HMAC_SHA1)
    {
        scs_set_error(ctx, SCS_ERR_IMPL, "unsupported cipherset");
        return -1;
    }

    EVP_CIPHER_CTX_init(&c);

    if (!EVP_EncryptInit_ex(&c, EVP_aes_128_cbc(), NULL, ks->key, ats->iv) 
            || !EVP_EncryptUpdate(&c, ats->data, &sz, ats->data, ats->data_sz) 
            || !EVP_EncryptFinal_ex(&c, ats->data + sz, &tmp_sz) 
            || !EVP_CIPHER_CTX_cleanup(&c))
    {
        scs_set_error(ctx, SCS_ERR_CRYPTO, "openssl error: %s",
                ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    EVP_CIPHER_CTX_cleanup(&c);

    return 0;
}

int openssl_dec (scs_t *ctx, scs_keyset_t *ks)
{
    EVP_CIPHER_CTX c;
    int tmp_sz, sz;
    scs_atoms_t *ats = &ctx->atoms;

    if (ks->cipherset != AES_128_CBC_HMAC_SHA1)
    {
        scs_set_error(ctx, SCS_ERR_IMPL, "unsupported cipherset");
        return -1;
    }

    EVP_CIPHER_CTX_init(&c);

    if (!EVP_DecryptInit_ex(&c, EVP_aes_128_cbc(), NULL, ks->key, ats->iv) 
            || !EVP_DecryptUpdate(&c, ats->data, &sz, ats->data, ats->data_sz) 
            || !EVP_DecryptFinal_ex(&c, ats->data + sz, &tmp_sz) 
            || !EVP_CIPHER_CTX_cleanup(&c))
    {
        scs_set_error(ctx, SCS_ERR_CRYPTO, "openssl error: %s",
                ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    EVP_CIPHER_CTX_cleanup(&c);

    return 0;
}

int openssl_tag (scs_t *ctx, scs_keyset_t *ks)
{
    HMAC_CTX c;
    scs_atoms_t *ats = &ctx->atoms;

    if (ks->cipherset != AES_128_CBC_HMAC_SHA1)
    {
        scs_set_error(ctx, SCS_ERR_IMPL, "unsupported cipherset");
        return -1;
    }

    HMAC_CTX_init(&c);

    size_t edata_len = strlen(ats->b64_data);
    size_t etstamp_len = strlen(ats->b64_tstamp);
    size_t etid_len = strlen(ats->b64_tid);
    size_t eiv_len = strlen(ats->b64_iv);

#if OPENSSL_VERSION_NUMBER < 0x10000000L
    HMAC_Init_ex(&c, ks->hkey, ks->hkey_sz, EVP_sha1(), NULL);

    HMAC_Update(&c, (unsigned char *) ats->b64_data, edata_len);
    HMAC_Update(&c, (unsigned char *) "|", 1);
    HMAC_Update(&c, (unsigned char *) ats->b64_tstamp, etstamp_len);
    HMAC_Update(&c, (unsigned char *) "|", 1);
    HMAC_Update(&c, (unsigned char *) ats->b64_tid, etid_len);
    HMAC_Update(&c, (unsigned char *) "|", 1);
    HMAC_Update(&c, (unsigned char *) ats->b64_iv, eiv_len);

    HMAC_Final(&c, ats->tag, (unsigned int *) &ats->tag_sz);
#else
    if (!HMAC_Init_ex(&c, ks->hkey, ks->hkey_sz, EVP_sha1(), NULL)
            || !HMAC_Update(&c, (unsigned char *) ats->b64_data, edata_len);
            || !HMAC_Update(&c, (unsigned char *) "|", 1);
            || !HMAC_Update(&c, (unsigned char *) ats->b64_tstamp, etstamp_len)
            || !HMAC_Update(&c, (unsigned char *) "|", 1);
            || !HMAC_Update(&c, (unsigned char *) ats->b64_tid, etid_len)
            || !HMAC_Update(&c, (unsigned char *) "|", 1);
            || !HMAC_Update(&c, (unsigned char *) ats->b64_iv, eiv_len)
            || !HMAC_Final(&c, ats->tag, (unsigned int *) &ats->tag_sz))
    {
        scs_set_error(ctx, SCS_ERR_CRYPTO, "openssl error: %s", 
                ERR_error_string(ERR_get_error(), NULL));
        HMAC_CTX_cleanup(&c);

        return -1;
    }
#endif  /* OpenSSL < 1.0.0 */

    HMAC_CTX_cleanup(&c);

    return 0;
}

void openssl_term (void) 
{
    EVP_cleanup();
}

static int rng_init (void)
{
    size_t i;
    uint32_t r[32]; /* 1024-bit */

#ifdef HAVE_ARC4RANDOM
    for (i = 0; i < sizeof r / sizeof(uint32_t); ++i)
        r[i] = arc4random();
#else
    srand((unsigned) &i);
    for (i = 0; i < sizeof r / sizeof(uint32_t); ++i)
        r[i] = (uint32_t) rand();
#endif  /* HAVE_ARC4RANDOM */

    RAND_seed(r, sizeof r);

    return 0;
}
