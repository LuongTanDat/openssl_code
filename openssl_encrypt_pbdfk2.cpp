#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
using namespace std;

int encrypt(FILE *ifp, FILE *ofp, const char *pass, int iter)
{
    const unsigned BUFSIZE = 4096;
    unsigned char *read_buf = (unsigned char *)malloc(BUFSIZE * sizeof(unsigned char));
    unsigned char *cipher_buf;
    unsigned blocksize;
    int out_len;
    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];

    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    int iklen = EVP_CIPHER_key_length(cipher);
    int ivlen = EVP_CIPHER_iv_length(cipher);
    unsigned char keyivpair[iklen + ivlen];
    unsigned char salt[8];
    if (!(RAND_bytes(salt, sizeof(salt))))
    {
        fprintf(stderr, "Call to %s failed\n", __func__);
        return 0; /* 0 designates error here */
    }

    PKCS5_PBKDF2_HMAC((char *)pass, -1, salt, sizeof(salt), iter, EVP_sha512(), iklen + ivlen, keyivpair);

    memcpy(key, keyivpair, iklen);
    memcpy(iv, keyivpair + iklen, ivlen);
    cout << key << " " << iv << endl;
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();

    EVP_CipherInit(ctx, EVP_aes_256_cbc(), key, iv, 1);
    blocksize = EVP_CIPHER_CTX_block_size(ctx);
    cipher_buf = (unsigned char *)malloc((BUFSIZE + blocksize) * sizeof(unsigned char));

    // Generate the actual key IV pair

    fwrite("Salted__", sizeof(unsigned char), 8, ofp);
    fwrite(salt, sizeof(unsigned char), 8, ofp);
    while (1)
    {

        // Read in data in blocks until EOF. Update the ciphering with each read.

        int numRead = fread(read_buf, sizeof(unsigned char), BUFSIZE, ifp);
        EVP_CipherUpdate(ctx, cipher_buf, &out_len, read_buf, numRead);
        fwrite(cipher_buf, sizeof(unsigned char), out_len, ofp);
        if (numRead < BUFSIZE)
        { // EOF
            break;
        }
    }

    // Now cipher the final block and write it out.

    EVP_CipherFinal(ctx, cipher_buf, &out_len);
    fwrite(cipher_buf, sizeof(unsigned char), out_len, ofp);

    // Free memory

    free(cipher_buf);
    free(read_buf);
}

int decrypt(FILE *ifp, FILE *ofp, const char *pass, int iter)
{

    const unsigned BUFSIZE = 4096;
    unsigned char *read_buf = (unsigned char *)malloc(BUFSIZE * sizeof(unsigned char));
    unsigned char *cipher_buf;
    unsigned blocksize;
    int out_len;
    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];

    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    int iklen = EVP_CIPHER_key_length(cipher);
    int ivlen = EVP_CIPHER_iv_length(cipher);
    unsigned char keyivpair[iklen + ivlen];
    unsigned char salt[8];
    int numRead = fread(salt, sizeof(unsigned char), 8, ifp);
    numRead = fread(salt, sizeof(unsigned char), 8, ifp);
    PKCS5_PBKDF2_HMAC((char *)pass, -1, salt, sizeof(salt), iter, EVP_sha512(), iklen + ivlen, keyivpair);

    memcpy(key, keyivpair, iklen);
    memcpy(iv, keyivpair + iklen, ivlen);
    cout << key << " " << iv << endl;
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();

    EVP_CipherInit(ctx, EVP_aes_256_cbc(), key, iv, 0);
    blocksize = EVP_CIPHER_CTX_block_size(ctx);
    cipher_buf = (unsigned char *)malloc((BUFSIZE + blocksize) * sizeof(unsigned char));

    // Generate the actual key IV pair

    while (1)
    {

        // Read in data in blocks until EOF. Update the ciphering with each read.

        numRead = fread(read_buf, sizeof(unsigned char), BUFSIZE, ifp);
        EVP_CipherUpdate(ctx, cipher_buf, &out_len, read_buf, numRead);
        fwrite(cipher_buf, sizeof(unsigned char), out_len, ofp);
        if (numRead < BUFSIZE)
        { // EOF
            break;
        }
    }

    // Now cipher the final block and write it out.

    EVP_CipherFinal(ctx, cipher_buf, &out_len);
    fwrite(cipher_buf, sizeof(unsigned char), out_len, ofp);

    // Free memory

    free(cipher_buf);
    free(read_buf);
}

int main(int argc, char *argv[])
{
    if (argc != 6)
    {
        cout << "Input missing. Template: mode input output pass iter" << endl;
        return 1;
    }
    string mode = argv[1];
    string path_input = argv[2];
    string path_output = argv[3];
    string pass = argv[4];
    char *p;
    int iter = strtol(argv[5], &p, 10);
    if (*p != '\0')
    {
        cout << "error iterator should be number" << endl;
    }
    FILE *fIN, *fOUT;
    if (mode == "enc")
    {
        cout << path_input.c_str() << endl;
        fIN = fopen(path_input.c_str(), "rb");
        fOUT = fopen(path_output.c_str(), "wb");
        encrypt(fIN, fOUT, pass.c_str(), iter);
        fclose(fIN);
        fclose(fOUT);
    }
    if (mode == "dec")
    {
        fIN = fopen(path_input.c_str(), "rb");
        fOUT = fopen(path_output.c_str(), "wb");
        decrypt(fIN, fOUT, pass.c_str(), iter);
        fclose(fIN);
        fclose(fOUT);
    }

    return 0;
}