#include <stdarg.h>
#include <stdio.h>
#include "utils.h"

int scs_set_error (scs_t *scs, scs_err_t rc, const char *fmt, ...)
{
    int ret;
    va_list ap;
       
    va_start(ap, fmt);
    ret = vsnprintf(scs->estr, sizeof scs->estr, fmt, ap);
    scs->rc = rc;
    va_end(ap);

    return ret;
}
