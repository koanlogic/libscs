#ifndef _SCS_UTILS_H_
#define _SCS_UTILS_H_

#include "scs_conf.h"
#include "scs.h"
#include "scs_priv.h"
#include "utils.h"

int scs_set_error (scs_t *scs, scs_err_t rc, const char *fmt, ...);
void debug_print_buf (const char *label, const uint8_t *b, size_t b_sz);

#endif  /* _SCS_UTILS_H_ */
