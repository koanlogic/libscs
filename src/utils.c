#include <stdarg.h>
#include <stdio.h>
#include "utils.h"

int scs_set_error (scs_t *ctx, scs_err_t rc, const char *fmt, ...)
{
    int ret;
    va_list ap;

    if (ctx == NULL)
        return -1;

    va_start(ap, fmt);
    ret = vsnprintf(ctx->estr, sizeof ctx->estr, fmt, ap);
    ctx->rc = rc;
    va_end(ap);

    return ret;
}

void debug_print_buf (const char *label, const uint8_t *b, size_t b_sz)
{
    unsigned int i;

    printf("<%s>", label);
    for (i = 0; i < b_sz; ++i)
    {
        if (i % 8 == 0)
            printf("\n");

        printf("%02x ", b[i]);
    }
    printf("\n</%s>\n", label);
}
