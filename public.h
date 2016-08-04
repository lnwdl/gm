/* Copyright (C) lnwdl (lnwdl@163.com)
 * All rights reserved.
 *
 * Define && Implement some public macros && funcs.
 */

#ifndef __PUBLIC_H__
#define __PUBLIC_H__

#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/ec.h>

#define DEBUG_MSG(format, ...) \
    fprintf(stdout, "%s:%d(%s)"format, \
            __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)

#define ERROR_MSG(format, ...) \
    fprintf(stderr, "%s:%d(%s)"format, \
            __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)

void ShwHexBuf(const void *in, const size_t ilen);
char *hex2oct(const unsigned char *in, const size_t ilen);
int BN_bn2bin_gm(BIGNUM *a, unsigned char *out, const int degree);

int getUserExtInfo(EC_KEY *eckey,
        const EC_POINT *pub, const EVP_MD *md,
        const unsigned char *ID, const size_t IDlen,
        unsigned char *out, size_t *outlen);

void BNPrintf(const BIGNUM *bn);

#define PrintBN(bn) \
    do {    \
        fprintf(stdout, #bn": ");   \
        BNPrintf(bn);   \
    } while (0)

char *getDefID(void);
void setDefID(const char *id);

EC_GROUP *sm2_create_group(const EC_METHOD *meth, const char *in_p, 
        const char *in_a, const char *in_b,
        const char *in_gx, const char *in_gy,
        const char *in_o, const char *in_cf);

EC_KEY *sm2_create_eckey(const EC_GROUP *group, const char *in_pri,
        const char *in_pubx, const char *in_puby);

/* this function is come from OpenSSL */
int myECDH_KDF_X9_62(unsigned char *out, size_t outlen, 
        const unsigned char *Z, size_t Zlen,
        const unsigned char *sinfo, size_t sinfolen,
        const EVP_MD *md);

#endif
