#ifndef _MISSING_H_
#define _MISSING_H_

#include <stddef.h>

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif  /* !HAVE_STRLCPY */

#endif  /* !_MISSING_H_ */
