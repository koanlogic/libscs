#ifndef _CYASSL_DRV_H_
#define _CYASSL_DRV_H_

#include "scs.h"

int cyassl_init (void);
int cyassl_gen_iv (scs_t *scs);
int cyassl_enc (scs_t *scs);
int cyassl_dec (scs_t *scs, scs_keyset_t *ks);
int cyassl_tag (scs_t *scs);
void cyassl_term (void);

#endif  /* _CYASSL_DRV_H_ */
