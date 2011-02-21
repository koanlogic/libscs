#ifndef _B64_H_
#define _B64_H_

#include <stddef.h>
#include <stdint.h>

/* IN: binary data, OUT: B64 string (possibly NUL-terminated). */
int base64_encode (const uint8_t *in, size_t in_sz, char *out, size_t out_sz);

/* IN: B64 string, OUT: binary data. */
int base64_decode (const char *in, size_t in_sz, uint8_t *out, size_t *out_sz);

#endif  /* !_B64_H_ */
