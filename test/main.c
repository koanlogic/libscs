#include <stdlib.h>
#include <string.h>
#include "scs.h"

#define __COOKIE "NID=44=pGlr0kC4zkb2FZc4FNTqFDGpL7jLsPkvgTtgeRQ1oWsIQL3hXy0w38pHqmEL_JTepSoxTFw7ix_XrHpuniGHXCSOkyM71og81ZlaCQsbkoUJr2Pc9XUzKSoYQgWLDiST"

#define COOKIE  "0123456789qwertyuiopasdfghjklzxc"

typedef char buf_t[8192];

int main (void)
{
    scs_t *scs = NULL;
    uint8_t k[16] = { 'd', 'e', 'a', 'd', 'b', 'e', 'e', 'f' }, *state;
    uint8_t hk[20] = { 'D', 'E', 'A', 'D', 'B', 'E', 'E', 'F' };

    buf_t data, iv, authtag, atime, tid;

    data[0] = iv[0] = authtag[0] = atime[0] = '\0';

    if (scs_init("tid", AES_128_CBC_HMAC_SHA1, k, hk, 1, 3600, &scs) != SCS_OK)
        goto err;

    if (scs_encode(scs, (uint8_t *) COOKIE, strlen(COOKIE)))
        goto err;

    (void) strncpy(data, scs_data(scs), sizeof(buf_t) - 1);
    (void) strncpy(atime, scs_atime(scs), sizeof(buf_t) - 1);
    (void) strncpy(iv, scs_iv(scs), sizeof(buf_t) - 1);
    (void) strncpy(authtag, scs_authtag(scs), sizeof(buf_t) - 1);
    (void) strncpy(tid, scs_tid(scs), sizeof(buf_t) - 1);

    if (scs_decode(scs, data, atime, iv, authtag, tid))
        goto err;

    scs_term(scs);

    return EXIT_SUCCESS;
err:
    scs_term(scs);

    return EXIT_FAILURE;
}
