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

static int rng_init (void);

int openssl_init (void)
{
    /* Add just what is strictly needed. */
    EVP_add_cipher(EVP_aes_128_cbc());
    EVP_add_digest(EVP_sha1());

    return 0;
}

int openssl_gen_iv (scs_t *scs)
{
    scs_keyset_t *ks = &scs->cur_keyset;

    if (rng_init() == -1)
        return -1;

    if (!RAND_bytes(scs->iv, ks->block_sz))
        return -1;

#ifdef FIXED_PARAMS
    memset(scs->iv, 0, ks->block_sz);
#endif  /* FIXED_PARAMS */

    return 0;
}

int openssl_enc (scs_t *scs, unsigned char *in, size_t in_sz, uint8_t *out)
{
    EVP_CIPHER_CTX c;
    int tmp_sz, out_sz;
    scs_keyset_t *ks = &scs->cur_keyset;

    EVP_CIPHER_CTX_init(&c);

    if (!EVP_EncryptInit_ex(&c, EVP_aes_128_cbc(), NULL, ks->key, scs->iv) ||
            !EVP_EncryptUpdate(&c, out, &out_sz, in, in_sz) ||
            !EVP_EncryptFinal_ex(&c, out + out_sz, &tmp_sz) ||
            !EVP_CIPHER_CTX_cleanup(&c))
        return -1;

    out_sz += tmp_sz;

    EVP_CIPHER_CTX_cleanup(&c);

    assert(ENC_LENGTH(in_sz, ks->block_sz) == (size_t) out_sz);

    return 0;
}

int openssl_tag (scs_t *scs)
{
    HMAC_CTX c;
    scs_keyset_t *ks = &scs->cur_keyset;

    HMAC_CTX_init(&c);

#if OPENSSL_VERSION_NUMBER < 0x10000000L
    HMAC_Init_ex(&c, ks->hkey, ks->hkey_sz, EVP_sha1(), NULL);
    HMAC_Update(&c, (unsigned char *) scs->b64_data, strlen(scs->b64_data));
    HMAC_Update(&c, (unsigned char *) scs->b64_atime, strlen(scs->b64_atime));
    HMAC_Update(&c, (unsigned char *) scs->b64_tid, strlen(scs->b64_tid));
    HMAC_Update(&c, (unsigned char *) scs->b64_iv, strlen(scs->b64_iv));
    HMAC_Final(&c, scs->tag, (unsigned int *) &scs->tag_sz);
#else
    if (!HMAC_Init_ex(&c, ks->hkey, ks->hkey_sz, EVP_sha1(), NULL) || 
            || !HMAC_Update(&c, (unsigned char *) scs->b64_data, 
                            strlen(scs->b64_data))
            || !HMAC_Update(&c, (unsigned char *) scs->b64_atime, 
                            strlen(scs->b64_atime))
            || !HMAC_Update(&c, (unsigned char *) scs->b64_tid, 
                            strlen(scs->b64_tid))
            || !HMAC_Update(&c, (unsigned char *) scs->b64_iv, 
                            strlen(scs->b64_iv))
            || !HMAC_Final(&c, scs->tag, (unsigned int *) &scs->tag_sz))
    {
        char ebuf[128]; /* According to ERR_error_string man page it must be
                           at least 120 bytes long. */
        scs_set_error(scs, SCS_ERR_CRYPTO, "openssl error: %s", 
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
