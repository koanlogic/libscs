#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include "base64.h"

static const char E[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/* Compute offsets (+1) in E (also works as truth table for is_base64url_c). */
static const int D[256] = {
    0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  63, 0,  0,   /* - */
    53, 54, 55, 56, 57, 58, 59, 60,  /* 0-7 */
    61, 62, 0,  0,  0,  0,  0,  0,   /* 8,9 */
    0,  1,  2,  3,  4,  5,  6,  7,   /* A-G */
    8,  9,  10, 11, 12, 13, 14, 15,  /* H-O */
    16, 17, 18, 19, 20, 21, 22, 23,  /* P-W */
    24, 25, 26, 0,  0,  0,  0,  64,  /* X-Z,_ */
    0,  27, 28, 29, 30, 31, 32, 33,  /* a-g */
    34, 35, 36, 37, 38, 39, 40, 41,  /* h-o */
    42, 43, 44, 45, 46, 47, 48, 49,  /* p-w */
    50, 51, 52, 0,  0,  0,  0,  0    /* x-z */
};

static inline int val(int c);
static inline int is_base64url_c(int c);
static inline size_t chunk_encode(uint8_t in[3], size_t in_sz, char out[4],
        size_t out_sz);
static inline int chunk_decode(char in[4], size_t in_sz, uint8_t out[3],
        size_t out_sz);

/* IN: binary data, OUT: B64 string (*not* NUL-terminated).
 * 'pout_sz' is a value-result argument carrying the size of 'out' on
 * input and the number of encoded bytes on output. */
int base64url_encode(const uint8_t *in, size_t in_sz, char *out,
        size_t *pout_sz)
{
    size_t i, len, out_sz = *pout_sz;
    uint8_t buf[3]; 
    char *pout;

    for (pout = out; in_sz; )
    {
        /* Get three bytes from 'in'. */
        for (len = 0, i = 0; i < 3; ++i)
        {
            if (in_sz && in_sz-- > 0)   /* Avoid wrapping around in_sz. */
            {
                buf[i] = *in++;
                ++len;
            }
        }

        /* See if we've harvested enough data to call the block encoder. */
        if (len)
        {
            size_t outlen = chunk_encode(buf, len, pout, out_sz);

            if (outlen)
            {
                out_sz -= outlen;
                pout += outlen;
            }
            else
                return -1;
        }
    }

    /* Update the encoded length counter. */
    *pout_sz -= out_sz;

    return 0;
}

/* IN: base64url encoded string (not NUL-terminated). OUT: the corresponding
 * decoded buffer. */
int base64url_decode(const char *in, size_t in_sz, uint8_t *out,
        size_t *out_sz)
{
    char buf[4];
    size_t i, len, tot_sz = *out_sz;
    uint8_t *pout;

    for (pout = out; in_sz; )
    {
        /* Get a 4-bytes chunk (may be less than 4, actually). */
        for (len = 0, i = 0; i < 4; ++i)
        {
            if (in_sz && in_sz-- > 0)   /* Avoid wrapping around in_sz. */
            {
                buf[i] = *in++;

                if (!is_base64url_c(buf[i]))
                    return -1;

                ++len;
            }
        }

        /* Decode the chunk into its 3-bytes' binary data. */
        if (len)
        {
            int outlen = chunk_decode(buf, len, pout, tot_sz);

            if (outlen)
            {
                tot_sz -= outlen;
                pout += outlen;
            }
            else
                return -1;
        }
    }

    *out_sz -= tot_sz;

    return 0;
}

static inline int is_base64url_c(int c) 
{
    return D[c];
}

static inline int val(int c) 
{
    return (D[c] - 1);
}

/* Encode 'in_sz' bytes to from 'in' to 'out'.  Return the number 
 * of encoded bytes (2 to 4) or '0' on error. */
static inline size_t chunk_encode(uint8_t in[3], size_t in_sz, char out[4],
        size_t out_sz)
{
    size_t nenc = 4;

    if (!in_sz || in_sz > 3)
        return 0;

    /* Make sure unused bytes don't introduce noise. */
    memset(in + in_sz, 0, 3 - in_sz);

    out[0] = E[in[0] >> 2];
    out[1] = E[((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4)];

    if (in_sz >= 2)
        out[2] = E[((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6)];
    else
        nenc -= 1;

    if (in_sz == 3)
        out[3] = E[in[2] & 0x3f];
    else
        nenc -= 1;

    return (out_sz >= nenc) ? nenc : 0;
}

/* Decode a chunk of 'in_sz' (at most 4) base64url encoded chars. */
static inline int chunk_decode(char in[4], size_t in_sz, uint8_t out[3],
        size_t out_sz)
{
    size_t ndec;
    int r1, r2;

    if (!in_sz || in_sz > 4)
        return 0;

    /* Make sure unused bytes don't introduce noise. */
    memset(in + in_sz, 0, 4 - in_sz);

    /* Compute the right leg of the 2nd and 3rd sextets. */
    r1 = val(in[1]) & 0x0f;
    r2 = val(in[2]) & 0x03;

    /* Compute the number of decoded bytes. */
    switch (in_sz)
    {
        case 1: ndec = 1; break;
        case 2: ndec = r1 ? 2 : 1; break;
        case 3: ndec = r2 ? 3 : 2; break;
        case 4: ndec = 3; break;
    }

    out[0] = (val(in[0]) << 2) | (val(in[1]) >> 4);
    out[1] = r1 << 4 | val(in[2]) >> 2;
    out[2] = r2 << 6 | val(in[3]);

    return (out_sz >= ndec) ? ndec : 0;
}
