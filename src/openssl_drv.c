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
        scs_set_error(ctx, SCS_ERR_CRYPTO, "%s", "TODO get openssl error");
        return -1;
    }

    return 0;
}

int openssl_enc (scs_t *ctx)
{
    EVP_CIPHER_CTX c;
    int tmp_sz, out_sz;
    scs_atoms_t *ats = &ctx->atoms;
    scs_keyset_t *ks = &ctx->cur_keyset;

    if (ks->cipherset != AES_128_CBC_HMAC_SHA1)
    {
        scs_set_error(ctx, SCS_ERR_IMPL, "unsupported cipherset");
        return -1;
    }

    EVP_CIPHER_CTX_init(&c);

    if (!EVP_EncryptInit_ex(&c, EVP_aes_128_cbc(), NULL, ks->key, ats->iv) 
            || !EVP_EncryptUpdate(&c, ats->data, &out_sz, ats->data, 
                                  ats->data_sz) 
            || !EVP_EncryptFinal_ex(&c, ats->data + out_sz, &tmp_sz) 
            || !EVP_CIPHER_CTX_cleanup(&c))
        return -1;

    out_sz += tmp_sz;

    EVP_CIPHER_CTX_cleanup(&c);

    return 0;
}

int openssl_dec (scs_t *ctx, scs_keyset_t *ks)
{
    EVP_CIPHER_CTX c;
    int tmp_sz, out_sz;
    scs_atoms_t *ats = &ctx->atoms;

    if (ks->cipherset != AES_128_CBC_HMAC_SHA1)
    {
        scs_set_error(ctx, SCS_ERR_IMPL, "unsupported cipherset");
        return -1;
    }

    EVP_CIPHER_CTX_init(&c);

    if (!EVP_DecryptInit_ex(&c, EVP_aes_128_cbc(), NULL, ks->key, ats->iv) 
            || !EVP_DecryptUpdate(&c, ats->data, &out_sz, ats->data, 
                                  ats->data_sz) 
            || !EVP_DecryptFinal_ex(&c, ats->data + out_sz, &tmp_sz) 
            || !EVP_CIPHER_CTX_cleanup(&c))
        return -1;

    out_sz += tmp_sz;

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

#if OPENSSL_VERSION_NUMBER < 0x10000000L
    HMAC_Init_ex(&c, ks->hkey, ks->hkey_sz, EVP_sha1(), NULL);

    HMAC_Update(&c, (unsigned char *) ats->b64_data, strlen(ats->b64_data));
    HMAC_Update(&c, (unsigned char *) "|", 1);
    HMAC_Update(&c, (unsigned char *) ats->b64_atime, strlen(ats->b64_atime));
    HMAC_Update(&c, (unsigned char *) "|", 1);
    HMAC_Update(&c, (unsigned char *) ats->b64_tid, strlen(ats->b64_tid));
    HMAC_Update(&c, (unsigned char *) "|", 1);
    HMAC_Update(&c, (unsigned char *) ats->b64_iv, strlen(ats->b64_iv));

    HMAC_Final(&c, ats->tag, (unsigned int *) &ats->tag_sz);
#else
    if (!HMAC_Init_ex(&c, ks->hkey, ks->hkey_sz, EVP_sha1(), NULL)
            || !HMAC_Update(&c, (unsigned char *) ats->b64_data, 
                            strlen(ats->b64_data))
            || !HMAC_Update(&c, (unsigned char *) "|", 1);
            || !HMAC_Update(&c, (unsigned char *) ats->b64_atime, 
                            strlen(ats->b64_atime))
            || !HMAC_Update(&c, (unsigned char *) "|", 1);
            || !HMAC_Update(&c, (unsigned char *) ats->b64_tid, 
                            strlen(ats->b64_tid))
            || !HMAC_Update(&c, (unsigned char *) "|", 1);
            || !HMAC_Update(&c, (unsigned char *) ats->b64_iv, 
                            strlen(ats->b64_iv))
            || !HMAC_Final(&c, ats->tag, (unsigned int *) &ats->tag_sz))
    {
        char ebuf[128]; /* According to ERR_error_string man page it must be
                           at least 120 bytes long. */
        scs_set_error(ctx, SCS_ERR_CRYPTO, "openssl error: %s", 
                ERR_error_string(ERR_get_error(), ebuf));
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

    for (i = 0; i < sizeof r; ++i)
        r[i] = arc4random();

    RAND_seed(r, sizeof r);

    return 0;
}
