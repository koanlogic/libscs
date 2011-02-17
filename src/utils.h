#ifndef _SCS_UTILS_H_
#define _SCS_UTILS_H_

#include "scs_conf.h"
#include "scs.h"
#include "scs_priv.h"
#include "utils.h"

int scs_set_error (scs_t *scs, scs_err_t rc, const char *fmt, ...);

#endif  /* _SCS_UTILS_H_ */
