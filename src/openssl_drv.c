#include <sys/time.h>
#include <assert.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/opensslv.h>
#include "openssl_drv.h"

typedef struct
{
    pid_t pid;
    long int t1, t2;
    void *stack;
} rng_seed_t;

static int rng_init (void);

int openssl_init (void)
{
    OpenSSL_add_all_algorithms();

    return 0;
}

int openssl_gen_iv (scs_t *scs)
{
    scs_keyset_t *ks = &scs->cur_keyset;

    if (rng_init() == -1)
        return -1;

    if (!RAND_bytes(scs->iv, ks->block_sz))
        return -1;

    return 0;
}

int openssl_enc (scs_t *scs, uint8_t *in, size_t in_sz, uint8_t *out)
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

    assert(in_sz + ks->block_sz == (size_t) out_sz);

    return 0;
}

int openssl_tag (scs_t *scs, const char *auth_blob)
{
    HMAC_CTX c;
    scs_keyset_t *ks = &scs->cur_keyset;

    HMAC_CTX_init(&c);

#if OPENSSL_VERSION_NUMBER < 0x10000000L
    HMAC_Init_ex(&c, ks->hkey, ks->hkey_sz, EVP_sha1(), NULL);
    HMAC_Update(&c, (unsigned char *) auth_blob, strlen(auth_blob));
    HMAC_Final(&c, scs->tag, (unsigned int *) &scs->tag_sz);
#else
    if (!HMAC_Init_ex(&c, ks->hkey, ks->hkey_sz, EVP_sha1(), NULL) ||
            !HMAC_Update(&c, (unsigned char *) auth_blob, strlen(auth_blob)) ||
            !HMAC_Final(&c, scs->tag, (unsigned int *) &scs->tag_sz))
        return -1;
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
    struct timeval tv;
    rng_seed_t seed;

    if (gettimeofday(&tv, NULL) == -1)
        return -1;

    seed.pid = getpid();
    seed.t1 = tv.tv_sec;
    seed.t2 = tv.tv_usec;
    seed.stack = (void *) &seed;

    RAND_seed((const void *) &seed, sizeof seed);

    return 0;
}
