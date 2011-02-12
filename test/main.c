#include <stdlib.h>
#include "scs.h"

int main (void)
{
    scs_t *scs = NULL;
    uint8_t k[16] = { 'd', 'e', 'a', 'd', 'b', 'e', 'e', 'f' };
    uint8_t hk[20] = { 'D', 'E', 'A', 'D', 'B', 'E', 'E', 'F' };

    if (scs_init("tid", AES_128_CBC_HMAC_SHA1, k, hk, 1, 3600, &scs) != SCS_OK)
        goto err;

    if (scs_outbound(scs, "mystate=myvalue") != SCS_OK)
        goto err;

    /* TODO */

    scs_term(scs);

    return EXIT_SUCCESS;
err:
    scs_term(scs);

    return EXIT_FAILURE;
}
