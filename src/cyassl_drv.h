#ifndef _CYASSL_DRV_H_
#define _CYASSL_DRV_H_

#include "scs.h"
#include "scs_priv.h"

int cyassl_init (void);
int cyassl_rand (scs_t *ctx, uint8_t *b, size_t b_sz);
int cyassl_enc (scs_t *scs);
int cyassl_dec (scs_t *scs, scs_keyset_t *ks);
int cyassl_tag (scs_t *ctx, scs_keyset_t *ks);
void cyassl_term (void);

#endif  /* _CYASSL_DRV_H_ */
