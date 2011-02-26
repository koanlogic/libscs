#include <config.h>
#include <types.h>
#include <ctc_hmac.h>
#include <ctc_aes.h>
#include <random.h>
#include <coding.h>

#include "cyassl_drv.h"
#include "utils.h"

int cyassl_init (void)
{
    return 0;
}

int cyassl_gen_iv (scs_t *ctx)
{
    RNG rng;
    scs_keyset_t *ks = &ctx->cur_keyset;
    scs_atoms_t *ats = &ctx->atoms;

    if (InitRng(&rng))
        return -1;

    RNG_GenerateBlock(&rng, ats->iv, ks->block_sz);

#ifdef FIXED_PARAMS
    memset(ats->iv, 0, ks->block_sz);
#endif  /* FIXED_PARAMS */

    return 0;
}

int cyassl_enc (scs_t *ctx)
{
    Aes aes;
    scs_atoms_t *ats = &ctx->atoms;
    scs_keyset_t *ks = &ctx->cur_keyset;

    if (ks->cipherset != AES_128_CBC_HMAC_SHA1)
    {
        scs_set_error(ctx, SCS_ERR_IMPL, "unsupported cipherset");
        return -1;
    }

    AesSetKey(&aes, ks->key, ks->key_sz, ats->iv, AES_ENCRYPTION);
    AesCbcEncrypt(&aes, ats->data, ats->data, ats->data_sz);

    return 0;
}

int cyassl_dec (scs_t *ctx, scs_keyset_t *ks)
{
    Aes aes;
    scs_atoms_t *ats = &ctx->atoms;

    if (ks->cipherset != AES_128_CBC_HMAC_SHA1)
    {
        scs_set_error(ctx, SCS_ERR_IMPL, "unsupported cipherset");
        return -1;
    }

    AesSetKey(&aes, ks->key, ks->key_sz, ats->iv, AES_DECRYPTION);
    AesCbcDecrypt(&aes, ats->data, ats->data, ats->data_sz);

    return 0;
}

int cyassl_tag (scs_t *ctx)
{
    Hmac hmac;
    scs_atoms_t *ats = &ctx->atoms;
    scs_keyset_t *ks = &ctx->cur_keyset;

    if (ks->cipherset != AES_128_CBC_HMAC_SHA1)
    {
        scs_set_error(ctx, SCS_ERR_IMPL, "unsupported cipherset");
        return -1;
    }

    HmacSetKey(&hmac, SHA, ks->hkey, ks->hkey_sz);

    HmacUpdate(&hmac, (byte *) ats->b64_data, strlen(ats->b64_data));
    HmacUpdate(&hmac, (byte *) "|", 1);
    HmacUpdate(&hmac, (byte *) ats->b64_atime, strlen(ats->b64_atime));
    HmacUpdate(&hmac, (byte *) "|", 1);
    HmacUpdate(&hmac, (byte *) ats->b64_tid, strlen(ats->b64_tid));
    HmacUpdate(&hmac, (byte *) "|", 1);
    HmacUpdate(&hmac, (byte *) ats->b64_iv, strlen(ats->b64_iv));

    HmacFinal(&hmac, ats->tag);

    ats->tag_sz = SHA_DIGEST_SIZE;

    return 0;
}

void cyassl_term (void) {}
