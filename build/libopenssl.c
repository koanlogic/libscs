#include <stdio.h>
#include <openssl/opensslv.h>
#include <openssl/evp.h>

int main()
{
    if (OPENSSL_VERSION_NUMBER < 0x00907000L) {
        printf("OpenSSL version 0.9.7 or better is required!\n");
        return 1;
    }

    EVP_add_cipher(EVP_aes_128_cbc());
    EVP_add_digest(EVP_sha1());

    return 0;
}
