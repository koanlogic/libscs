#ifndef _OPENSSL_DRV_H_
#define _OPENSSL_DRV_H_

#include "scs.h"

int openssl_init (void);
int openssl_gen_iv (scs_t *scs);
int openssl_enc (scs_t *scs);
int openssl_dec (scs_t *scs, scs_keyset_t *ks);
int openssl_tag (scs_t *scs);
void openssl_term (void);

#endif  /* _OPENSSL_DRV_H_ */
