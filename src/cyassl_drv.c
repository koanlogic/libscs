#include <config.h>
#include <types.h>
#include <ctc_hmac.h>
#include <ctc_aes.h>
#include <random.h>
#include <coding.h>

#include "cyassl_drv.h"

int cyassl_init (void)
{
    return 0;
}

int cyassl_gen_iv (scs_t *scs)
{
    RNG rng;
    scs_keyset_t *ks = &scs->cur_keyset;

    if (InitRng(&rng))
        return -1;

    RNG_GenerateBlock(&rng, scs->iv, ks->block_sz);

#ifdef FIXED_PARAMS
    memset(scs->iv, 0, ks->block_sz);
#endif  /* FIXED_PARAMS */

    return 0;
}

int cyassl_enc (scs_t *scs)
{
    Aes aes;
    scs_keyset_t *ks = &scs->cur_keyset;

    AesSetKey(&aes, ks->key, ks->key_sz, scs->iv, AES_ENCRYPTION);
    AesCbcEncrypt(&aes, scs->data, scs->data, scs->data_sz);

    return 0;
}

int cyassl_dec (scs_t *scs, scs_keyset_t *ks)
{
    Aes aes;
    
    AesSetKey(&aes, ks->key, ks->key_sz, scs->iv, AES_ENCRYPTION);
    AesCbcDecrypt(&aes, scs->data, scs->data, scs->data_sz);
    
    return 0;
}

int cyassl_tag (scs_t *scs)
{
    Hmac hmac;
    scs_keyset_t *ks = &scs->cur_keyset;

    HmacSetKey(&hmac, SHA, ks->hkey, ks->hkey_sz);
    HmacUpdate(&hmac, (byte *) scs->b64_data, strlen(scs->b64_data));
    HmacUpdate(&hmac, (byte *) scs->b64_atime, strlen(scs->b64_atime));
    HmacUpdate(&hmac, (byte *) scs->b64_tid, strlen(scs->b64_tid));
    HmacUpdate(&hmac, (byte *) scs->b64_iv, strlen(scs->b64_iv));
    HmacFinal(&hmac, scs->tag);

    scs->tag_sz = SHA_DIGEST_SIZE;

    return 0;
}

void cyassl_term (void) {}
