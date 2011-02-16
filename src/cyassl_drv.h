#ifndef _CYASSL_DRV_H_
#define _CYASSL_DRV_H_

#include "scs.h"

int cyassl_init (void);
int cyassl_gen_iv (scs_t *scs);
int cyassl_enc (scs_t *scs, uint8_t *in, size_t in_sz, uint8_t *out);
int cyassl_tag (scs_t *scs);
void cyassl_term (void);

#endif  /* _CYASSL_DRV_H_ */
