#ifndef _OPENSSL_DRV_H_
#define _OPENSSL_DRV_H_

#include "scs.h"
#include "scs_priv.h"

int openssl_init (void);
int openssl_rand (scs_t *ctx, uint8_t *b, size_t b_sz);
int openssl_enc (scs_t *scs);
int openssl_dec (scs_t *scs, scs_keyset_t *ks);
int openssl_tag (scs_t *scs, scs_keyset_t *ks);
void openssl_term (void);

#endif  /* _OPENSSL_DRV_H_ */
