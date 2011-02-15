#ifndef _OPENSSL_DRV_H_
#define _OPENSSL_DRV_H_

#include "scs.h"

int openssl_init (void);
int openssl_gen_iv (scs_t *scs);
int openssl_enc (scs_t *scs, uint8_t *in, size_t in_sz, uint8_t *out);
int openssl_tag (scs_t *scs, const char *auth_blob);
void openssl_term (void);

#endif  /* _OPENSSL_DRV_H_ */
