#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

#include "scs.h"

typedef struct
{
    /* 
     * Overall operation. 
     */
    enum {
        OP_ENCODE,                      /* -E (default operation.) */
        OP_DECODE,                      /* -D */
        OP_ENCODE_AND_DECODE,           /* -A */
        OP_ENCODE_REFRESH_AND_DECODE,   /* -R */
        OP_MAX
    } op;

    /* 
     * Input type.
     */
    enum {
        IN_TYPE_STRING_AUTO,            /* Default input. */
        IN_TYPE_STRING,                 /* -s <state string> */
        IN_TYPE_FILE,                   /* -f <filename>*/
        IN_TYPE_COOKIE_VALUE            /* -c <cookie-value> */
    } in_type;

    /* 
     * Input.
     */
    char in_s[SCS_DATA_MAX];            /* Input state string. */
    char in_fn[FILENAME_MAX];           /* Input file name. */
    char in_cookie[SCS_COOKIE_MAX];     /* Input cookie-value. */

    /*
     * Output type.
     */ 
    enum {
        OUT_TYPE_COOKIE_VALUE,          /* Default output. */
        OUT_TYPE_DECODED_STATE_STRING,
        OUT_TYPE_DECODED_STATE_FILE,
        OUT_TYPE_VALIDATION_RESULT
    } out_type;

    /*
     * Test output ("big enough" string.)
     */ 
    char out_s[8192];

    /* 
     * Supplied key material (Initial and refreshed keyset, if non-auto.) 
     */
    char k[128],                        /* -k <key> */
         hk[128],                       /* -h <key> */
         K[128],                        /* -K <key> */
         HK[128],                       /* -H <key> */
         tid[SCS_TID_MAX];              /* -t <tid> */

    /* Time to live. */
    time_t ttl;                         /* -T <seconds> (default 3600.) */

    /* Compression. */
    int comp;                           /* -z (default disabled.) */


} run_t;

void init_params (run_t *ptest);
void parse_opts (int ac, char **av, run_t *ptest);
void usage (void);

void encode (run_t *t, scs_t *ctx);
void decode (run_t *t, scs_t *ctx);
void encode_and_decode (run_t *t, scs_t *ctx);
void encode_refresh_and_decode (run_t *t, scs_t *ctx);

void test_output (run_t *t, const char *s);

typedef void (*test_fun_t) (run_t *, scs_t *);

test_fun_t test_fun[OP_MAX] = {
    encode,
    decode,
    encode_and_decode,
    encode_refresh_and_decode
};

int main (int ac, char *av[])
{
    run_t test;
    scs_t *scs = NULL;

    init_params(&test);
    parse_opts(ac, av, &test);
    
    /* Initialize SCS context. */
    if (scs_init(test.tid[0] == '\0' ? SCS_TID_AUTO : test.tid, 
                 AES_128_CBC_HMAC_SHA1, 
                 (uint8_t *) (test.k[0] == '\0' ? SCS_KEY_AUTO : test.k),
                 (uint8_t *) (test.hk[0] == '\0' ? SCS_KEY_AUTO : test.hk),
                 test.comp ? SCS_DO_COMPRESS : SCS_DO_NOT_COMPRESS,
                 test.ttl,
                 &scs))
        errx(EXIT_FAILURE, "scs_init failed");

    /* Invoke the requested test driver. */
    test_fun[test.op](&test, scs);

    /* Reclaim resources. */
    scs_term(scs);

    return 0;
}

void parse_opts (int ac, char **av, run_t *ptest)
{
    int c;

    while ((c = getopt(ac, av, "c:f:s:zADERT:")) != -1)
    {
        switch (c)
        {
            case 'E':
                ptest->op = OP_ENCODE;
                break;
            case 'D':
                ptest->op = OP_DECODE;
                break;
            case 'A':
                ptest->op = OP_ENCODE_AND_DECODE;
                break;
            case 'R':
                ptest->op = OP_ENCODE_REFRESH_AND_DECODE;
                break;
            case 'z':
                ptest->comp = 1;
                break;
            case 'T':
                ptest->ttl = atoi(optarg);
                break;
            case 's':
                ptest->in_type = IN_TYPE_STRING;
                strlcpy(ptest->in_s, optarg, sizeof ptest->in_s);
                break;
            case 'f':
                ptest->in_type = IN_TYPE_FILE;
                strlcpy(ptest->in_fn, optarg, sizeof ptest->in_fn);
                break;
            case 'c':
                ptest->in_type = IN_TYPE_COOKIE_VALUE;
                strlcpy(ptest->in_cookie, optarg, sizeof ptest->in_cookie);
                break;
            default:
                usage();
        }
    }

    return;
}

void init_params (run_t *ptest)
{
    ptest->op = OP_ENCODE;
    ptest->in_type = IN_TYPE_STRING_AUTO;
    ptest->in_s[0] = ptest->in_fn[0] = ptest->in_cookie[0] = '\0';
    ptest->out_type = OUT_TYPE_COOKIE_VALUE;
    ptest->k[0] = ptest->hk[0] = ptest->K[0] = ptest->HK[0] = '\0';
    ptest->tid[0] = '\0';
    ptest->ttl = 3600;
    ptest->comp = 0;

    return;
}

void usage (void)
{
    const char *opts = "[opts]";

    errx(EXIT_FAILURE, "%s", opts);
}

void encode (run_t *t, scs_t *ctx)
{
    const uint8_t *s;
    size_t s_sz;
    char cookie[SCS_COOKIE_MAX];

    /* Get state from the supplied source. */
    switch (t->in_type)
    {
        case IN_TYPE_STRING_AUTO:
            s = (const uint8_t *) "a test string";
            s_sz = strlen((const char *) s);
            break;
        case IN_TYPE_STRING:
            s = (const uint8_t *) &t->in_s[0];
            s_sz = strlen((const char *) s);
            break;
        case IN_TYPE_FILE:
            errx(EXIT_FAILURE, "TODO input from file");
        case IN_TYPE_COOKIE_VALUE:
            errx(EXIT_FAILURE, "cookie-value is not a valid input to encode");
    }

    if (scs_encode(ctx, s, s_sz, cookie) == NULL)
        errx(EXIT_FAILURE, "%s", scs_err(ctx));

    test_output(t, cookie);

    return;
}

void test_output (run_t *t, const char *s)
{
    /* TODO */
    fprintf(stdout, "%s\n", s);
}

void decode (run_t *t, scs_t *ctx)
{
    /* TODO */
    return;
}

void encode_and_decode (run_t *t, scs_t *ctx)
{
    /* TODO */
    return;
}

void encode_refresh_and_decode (run_t *t, scs_t *ctx)
{
    /* TODO */
    return;
}
