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
        OUT_TYPE_STRING,                /* Default output. */
        OUT_TYPE_FILE                   /* -o <filename> */
    } out_type;

    enum {
        OUT_WHAT_ALL,                   /* Default print out everything. */
        OUT_WHAT_ENCODE,                /* -e: only the encoded value. */
        OUT_WHAT_DECODE                 /* -d: only the decoded value. */
    } out_what;

    /*
     * Output file name in case of OUT_TYPE_DECODED_STATE_FILE.
     */ 
    char out_fn[FILENAME_MAX];

    /* 
     * Supplied key material (Initial and refreshed keyset, if non-auto.) 
     */
    char k[128],                        /* -k <key> */
         hk[128],                       /* -h <key> */
         K[128],                        /* -K <key> */
         HK[128],                       /* -H <key> */
         tid[SCS_TID_MAX],              /* -t <tid> */
         TID[SCS_TID_MAX];              /* -T <tid> */

    /* Time to live. */
    time_t ttl;                         /* -T <seconds> (default 3600.) */

    /* Compression. */
    int comp;                           /* -z (default disabled.) */

} run_t;

void init_params (run_t *ptest);
void parse_opts (int ac, char **av, run_t *ptest);
void usage (const char *progname);

void test_output (run_t *t, const char *s);
void read_from_file (const char *fn, uint8_t **pb, size_t *pb_sz);
void write_to_file (const char *fn, uint8_t *b, size_t b_sz);

void encode (run_t *t, scs_t *ctx);
void decode (run_t *t, scs_t *ctx);
void encode_and_decode (run_t *t, scs_t *ctx);
void encode_refresh_and_decode (run_t *t, scs_t *ctx);


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

    while ((c = getopt(ac, av, "c:def:h:k:l:o:t:s:zADEH:K:RT:")) != -1)
    {
        switch (c)
        {
            case 'e':
                ptest->out_what = OUT_WHAT_ENCODE;
                break;
            case 'd':
                ptest->out_what = OUT_WHAT_DECODE;
                break;
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
            case 'l':
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
            case 'o':
                ptest->out_type = OUT_TYPE_FILE;
                strlcpy(ptest->out_fn, optarg, sizeof ptest->out_fn);
                break;
            case 't':
                strlcpy(ptest->tid, optarg, sizeof ptest->tid);
                break;
            case 'k':
                strlcpy(ptest->k, optarg, sizeof ptest->k);
                break;
            case 'h':
                strlcpy(ptest->hk, optarg, sizeof ptest->hk);
                break;
            case 'H':
                strlcpy(ptest->K, optarg, sizeof ptest->K);
                break;
            case 'K':
                strlcpy(ptest->HK, optarg, sizeof ptest->HK);
                break;
            case 'T':
                strlcpy(ptest->TID, optarg, sizeof ptest->TID);
                break;
            default:
                usage(av[0]);
        }
    }

    return;
}

void init_params (run_t *ptest)
{
    ptest->op = OP_ENCODE;
    ptest->in_type = IN_TYPE_STRING_AUTO;
    ptest->in_s[0] = ptest->in_fn[0] = ptest->in_cookie[0] = '\0';
    ptest->out_type = OUT_TYPE_STRING;
    ptest->out_fn[0] = '\0';
    ptest->out_what = OUT_WHAT_ALL;
    ptest->k[0] = ptest->hk[0] = ptest->K[0] = ptest->HK[0] = '\0';
    ptest->tid[0] = ptest->TID[0] = '\0';
    ptest->ttl = 3600;
    ptest->comp = 0;

    return;
}

void usage (const char *progname)
{
    const char *fmt = 
        "\nUsage: %s [opts]\n\n"
        "    where \'opts\' is a combination of the following:\n\n"
        "    overall operations:\n"
        "       [-E]   encode only (default)\n"
        "       [-D]   decode only\n"
        "       [-A]   encode and decode\n"
        "       [-R]   encode, refresh and decode\n\n"
        "    input type (default is autogenerated state string):\n"
        "       [-s string]     state string\n"
        "       [-f file]       state file (whole contents, binary)\n"
        "       [-c string]     SCS cookie-value string\n\n"
        "    output type (default is to write result to stdout):\n"
        "       [-o file]       write result to file\n\n"
        "       [-e]            write only the encoded string\n"
        "       [-d]            write only the decoded string\n"
        "    keyset material:\n"
        "       [-t string]     SCS TID string\n"
        "       [-k string]     cipher key\n"
        "       [-h string]     HMAC key\n\n"
        "    refresh parameters:\n"
        "       [-T string]     new SCS TID string\n"
        "       [-K string]     new cipher key\n"
        "       [-H string]     new HMAC key\n\n"
        "    miscellaneous parameters:\n"
        "       [-z]            use compression (default NO)\n"
        "       [-l seconds]    SCS cookie time to live\n\n"
        ;

    (void) fprintf(stderr, fmt, progname);

    exit(EXIT_FAILURE);
}

void encode (run_t *t, scs_t *ctx)
{
    uint8_t *s;
    size_t s_sz;
    char cookie[SCS_COOKIE_MAX];

    /* Get state from the supplied source. */
    switch (t->in_type)
    {
        case IN_TYPE_STRING_AUTO:
            s = (uint8_t *) "a test string";
            s_sz = strlen((const char *) s);
            break;
        case IN_TYPE_STRING:
            s = (uint8_t *) &t->in_s[0];
            s_sz = strlen((const char *) s);
            break;
        case IN_TYPE_FILE:
            read_from_file(t->in_fn, &s, &s_sz);
            break;
        case IN_TYPE_COOKIE_VALUE:
            errx(EXIT_FAILURE, "cookie-value is not a valid input to encode");
    }

    if (scs_encode(ctx, s, s_sz, cookie) == NULL)
        errx(EXIT_FAILURE, "%s", scs_err(ctx));

    if (t->out_what != OUT_WHAT_DECODE)
        test_output(t, cookie);

    /* See if we have to chain operations. */
    if (t->op == OP_ENCODE_AND_DECODE 
            || t->op == OP_ENCODE_REFRESH_AND_DECODE)
    {
        (void) strlcpy(t->in_cookie, cookie, sizeof t->in_cookie);
        t->in_type = IN_TYPE_COOKIE_VALUE;
    }

    return;
}

void decode (run_t *t, scs_t *ctx)
{
    char *cookie, *s;
    size_t cookie_sz, s_sz;

    /* Get state from the supplied source. */
    switch (t->in_type)
    {
        case IN_TYPE_FILE:
            read_from_file(t->in_fn, (uint8_t **) &cookie, &cookie_sz);
            break;
        case IN_TYPE_COOKIE_VALUE:
            cookie = &t->in_cookie[0];
            cookie_sz = strlen(cookie);
            break;
        default:
            errx(EXIT_FAILURE, "cannot decode a non cookie-value");
    }

    if ((s = scs_decode(ctx, cookie, &s_sz)) == NULL)
        errx(EXIT_FAILURE, "%s", scs_err(ctx));

    s[s_sz] = '\0'; /* Check if needed. */

    if (t->out_what != OUT_WHAT_ENCODE)
        test_output(t, s);

    return;
}

void encode_and_decode (run_t *t, scs_t *ctx)
{
    encode(t, ctx);
    decode(t, ctx);
}

void encode_refresh_and_decode (run_t *t, scs_t *ctx)
{
    encode(t, ctx);

    if (scs_refresh_keyset(ctx, SCS_TID_AUTO, 
                (uint8_t *) (t->K[0] == '\0' ? SCS_KEY_AUTO : t->K),
                (uint8_t *) (t->HK[0] == '\0' ? SCS_KEY_AUTO : t->HK)))
        errx(EXIT_FAILURE, "%s", scs_err(ctx));

    decode(t, ctx);
}

void read_from_file (const char *fn, uint8_t **pb, size_t *pb_sz)
{
    long sz;
    uint8_t *b;
    FILE *fp;

    if ((fp = fopen(fn, "rb")) == NULL)
        err(EXIT_FAILURE, "%s", fn);

    if (fseek(fp, 0L, SEEK_END) == -1)
        err(EXIT_FAILURE, "seeking into %s", fn);

    /* Get file length. */
    sz = ftell(fp);
    rewind(fp);

    if ((b = malloc(sz)) == NULL)
        err(EXIT_FAILURE, "getting memory for reading from %s", fn);

    if (fread(b, sz, 1, fp) != 1)
        err(EXIT_FAILURE, "reading from %s", fn);

    (void) fclose(fp);

    *pb = b;
    *pb_sz = sz;

    return;
}

void write_to_file (const char *fn, uint8_t *b, size_t b_sz)
{
    FILE *fp;

    if ((fp = fopen(fn, "wb")) == NULL)
        err(EXIT_FAILURE, "%s", fn);

    if (fwrite(b, b_sz, 1, fp) != 1)
        err(EXIT_FAILURE, "%s", fn);

    return;
}

void test_output (run_t *t, const char *s)
{
    if (t->out_type == OUT_TYPE_STRING)
    {
        (void) fprintf(stdout, "%s\n", s);
        return;
    }

    write_to_file(t->out_fn, (uint8_t *) s, strlen(s));

    return;
}

