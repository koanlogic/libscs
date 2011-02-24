#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include "scs.h"

#define __STATE "NID=44=pGlr0kC4zkb2FZc4FNTqFDGpL7jLsPkvgTtgeRQ1oWsIQL3hXy0w38pHqmEL_JTepSoxTFw7ix_XrHpuniGHXCSOkyM71og81ZlaCQsbkoUJr2Pc9XUzKSoYQgWLDiST"

//#define STATE  "0123456789qwertyuiopasdfghjklzxc"
#define STATE  "1234567890123456"

int main (void)
{
    scs_t *scs = NULL;
    size_t orig_sz;
    char cookie[SCS_COOKIE_MAX], *orig;
    uint8_t ck[16] = { 'd', 'e', 'a', 'd', 'b', 'e', 'e', 'f' }, 
            hk[20] = { 'D', 'E', 'A', 'D', 'B', 'E', 'E', 'F' };


    if (scs_init("tid", AES_128_CBC_HMAC_SHA1, ck, hk, 1, 3600, &scs))
        errx(EXIT_FAILURE, "scs_init failed");

    printf("supplied state (len=%zu): %s\n", strlen(STATE) + 1, STATE);

    if (scs_encode(scs, (uint8_t *) STATE, strlen(STATE) + 1, cookie) == NULL)
        errx(EXIT_FAILURE, "scs_encode failed: %s", scs_err(scs));

    printf("encoded state (len=%zu): %s\n", strlen(cookie), cookie);

    if ((orig = scs_decode(scs, cookie, &orig_sz)) == NULL)
        errx(EXIT_FAILURE, "scs_decode failed: %s", scs_err(scs));

    printf("decoded state (len=%zu): %s\n", orig_sz, orig);

    scs_term(scs);

    return EXIT_SUCCESS;
}
