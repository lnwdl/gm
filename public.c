/* Copyright (C) lnwdl (lnwdl@163.com)
 * All rights reserved.
 *
 * Define && Implement some public macros && funcs.
 */

#include <stdio.h>
#include <string.h>
#include "public.h"
#include "evp_sm3.h"

void ShwHexBuf(const void *in, const size_t ilen)
{
    const unsigned char *buf = (const unsigned char *)in;
    size_t i, j;

    if (!buf || !ilen) {
        ERROR_MSG("parameters ERROR\n");
        return;
    }

    printf("========== [%d] ==========\n", ilen);
    for (i = 0, j = 0; i < ilen; ++i, ++j) {
        if (!(j % 16)) {
            if (j) {
                printf("\n");
            }
            printf("%08x:  ", j);
        }

        printf("%02x ", buf[i]);
    }
    printf("\n====================\n");
    fflush(stdout);
}

/* just for test, do not use it in release version 
 * becase there is a static variable.
 * */
char *hex2oct(const unsigned char *in, const size_t ilen)
{
    size_t i;
    static char buf[512];

    for (i = 0; i < ilen && i < sizeof (buf); ++i) {
        sprintf(buf + i * 2, "%02x", in[i]);
    }

    return buf;
}

/* In GM specification, all BIGNUM must be extend */
int BN_bn2bin_gm(BIGNUM *a, unsigned char *out, const int degree)
{
    int bbytes, dbytes, padlen;

    /* if a is 0, we also need to extend it */
    //if (!a || !out || BN_is_zero(a)) {
    if (!a || !out) {
        return 0;
    }

    bbytes = (BN_num_bits(a) + 7) / 8 ;
    dbytes = (degree + 7) / 8;
    if (dbytes <= bbytes) {
        return BN_bn2bin(a, out);
    }

    padlen = dbytes - bbytes;
    memset(out, 0, padlen);

    return BN_bn2bin(a, out + padlen) + padlen;
}

/* from GM/T 003.1-2012 4.2.5/4.2.6 */
int getUserExtInfo(EC_KEY *eckey, 
        const EC_POINT *pub, const EVP_MD *md,
        const unsigned char *ID, const size_t IDlen,
        unsigned char *out, size_t *outlen)
{
    EVP_MD_CTX mdctx;
    BN_CTX *bnctx = NULL;
    const EC_GROUP *group;
    const EC_POINT *G;
    BIGNUM *p, *a, *b, *Gx, *Gy, *Px, *Py;
    unsigned char ENTL[2];
    unsigned char bin[512]; /* long enough to hold curve point coordinate */
    unsigned int blen;
    int degree, ret = 0;

    if (!eckey || !pub || !md || !out || !outlen 
            || *outlen < (size_t)EVP_MD_size(md)) {
        goto error;
    }

    ENTL[1] = (IDlen * 8) & 0xff;
    ENTL[0] = ((IDlen * 8) >> 8) & 0xff;

    EVP_MD_CTX_init(&mdctx);

    EVP_DigestInit(&mdctx, md);
    EVP_DigestUpdate(&mdctx, ENTL, sizeof (ENTL));
    EVP_DigestUpdate(&mdctx, ID, IDlen);

    group = EC_KEY_get0_group(eckey);
    if (!group) {
        goto error;
    }

    G = EC_GROUP_get0_generator(group);
    if (!G) {
        goto error;
    }

    bnctx = BN_CTX_new();
    if (!bnctx) {
        goto error;
    }
    BN_CTX_start(bnctx);

    p = BN_CTX_get(bnctx);
    a = BN_CTX_get(bnctx);
    b = BN_CTX_get(bnctx);
    Gx = BN_CTX_get(bnctx);
    Gy = BN_CTX_get(bnctx);
    Px = BN_CTX_get(bnctx);
    Py = BN_CTX_get(bnctx);
    if (!p || !a || !b || !Gx || !Gy || !Px || !Py) {
        goto error;
    }

    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) 
            == NID_X9_62_prime_field) {
        if (!EC_GROUP_get_curve_GFp(group, p, a, b, NULL)) {
            goto error;
        }

        if (!EC_POINT_get_affine_coordinates_GFp(group, G, Gx, Gy, NULL)) {
            goto error;
        }

        if (!EC_POINT_get_affine_coordinates_GFp(group, pub, Px, Py, NULL)) {
            goto error;
        }
    } else {
#ifndef OPENSSL_NO_EC2M
        if (!EC_GROUP_get_curve_GF2m(group, p, a, b, NULL)) {
            goto error;
        }

        if (!EC_POINT_get_affine_coordinates_GF2m(group, G, Gx, Gy, NULL)) {
            goto error;
        }

        if (!EC_POINT_get_affine_coordinates_GF2m(group, pub, Px, Py, NULL)) {
            goto error;
        }
#else
        goto error;
#endif
    }

    degree = EC_GROUP_get_degree(group);
    blen = BN_bn2bin_gm(a, bin, degree);
    EVP_DigestUpdate(&mdctx, bin, blen);
    blen = BN_bn2bin_gm(b, bin, degree);
    EVP_DigestUpdate(&mdctx, bin, blen);
    blen = BN_bn2bin_gm(Gx, bin, degree);
    EVP_DigestUpdate(&mdctx, bin, blen);
    blen = BN_bn2bin_gm(Gy, bin, degree);
    EVP_DigestUpdate(&mdctx, bin, blen);
    blen = BN_bn2bin_gm(Px, bin, degree);
    EVP_DigestUpdate(&mdctx, bin, blen);
    blen = BN_bn2bin_gm(Py, bin, degree);
    EVP_DigestUpdate(&mdctx, bin, blen);

    EVP_DigestFinal(&mdctx, out, outlen);

    ret = 1;
error:
    EVP_MD_CTX_cleanup(&mdctx);
    if (bnctx) {
        BN_CTX_end(bnctx);
        BN_CTX_free(bnctx);
    }

    return ret;
}

void BNPrintf(const BIGNUM *bn)
{
	char *p = NULL;

	p = BN_bn2hex(bn);
	fprintf(stdout, "0x%s\n", p);
	OPENSSL_free(p);
}

/* come from GM/T 0009-2012 10 */
char *ID_default = "1234567812345678";
const char *ID_set = NULL;

char *getDefID(void)
{
    if (ID_set) {
        return (char *)ID_set;
    }

    return ID_default;
}

void setDefID(const char *id)
{
    ID_set = id;
}

/* used in sm2 test */
EC_GROUP *sm2_create_group(const EC_METHOD *meth, const char *in_p, 
        const char *in_a, const char *in_b,
        const char *in_gx, const char *in_gy,
        const char *in_o, const char *in_cf)
{
	EC_GROUP *group = NULL;
	BIGNUM *p = NULL, *a = NULL, *b = NULL, 
           *Gx = NULL, *Gy = NULL, *order = NULL, *cofactor = NULL;
    EC_POINT *generator = NULL;
    int ret = 0, is_prime;

    is_prime = (EC_METHOD_get_field_type(meth) == NID_X9_62_prime_field);

	group = EC_GROUP_new(meth); 
	if (!group) {
        ERROR_MSG("EC_GROUP_new ERROR\n");
        goto error;
    }

	p = BN_new();
	a = BN_new();
	b = BN_new();
	if (!p || !a || !b) {
        ERROR_MSG("BN_new ERROR\n");
        goto error;
    }

	BN_hex2bn(&p, in_p);
	BN_hex2bn(&a, in_a);
	BN_hex2bn(&b, in_b);
    if (is_prime) {
	    if (!EC_GROUP_set_curve_GFp(group, p, a, b, NULL)) {
            ERROR_MSG("EC_GROUP_set_curve_GFp ERROR\n");
            goto error;
        }
    } else {
# ifndef OPENSSL_NO_EC2M
	    if (!EC_GROUP_set_curve_GF2m(group, p, a, b, NULL)) {
            ERROR_MSG("EC_GROUP_set_curve_GFp ERROR\n");
            goto error;
        }
# else
        ERROR_MSG("OPENSSL_NO_EC2M ERROR\n");
        goto error;
# endif
    }

    generator = EC_POINT_new(group);
    if (!generator) {
        ERROR_MSG("EC_POINT_new ERROR\n");
        goto error;
    }

	Gx = BN_new();
	Gy = BN_new();
	order = BN_new();
    cofactor = BN_new();
	if (!Gx || !Gy || !order || !cofactor) {
        ERROR_MSG("BN_new ERROR\n");
        goto error;
    }

	BN_hex2bn(&Gx, in_gx);
    BN_hex2bn(&Gy, in_gy);
	BN_hex2bn(&order, in_o);
    if (is_prime) {
	    if (!EC_POINT_set_affine_coordinates_GFp(group, 
                    generator, Gx, Gy, NULL)) {
            ERROR_MSG("EC_POINT_set_affine_coordinates_GFp ERROR\n");
            goto error;
        }
    } else {
# ifndef OPENSSL_NO_EC2M
	    if (!EC_POINT_set_affine_coordinates_GF2m(group, 
                    generator, Gx, Gy, NULL)) {
            ERROR_MSG("EC_POINT_set_affine_coordinates_GFp ERROR\n");
            goto error;
        }
# else
        ERROR_MSG("OPENSSL_NO_EC2M ERROR\n");
        goto error;
# endif
    }

    if (EC_POINT_is_on_curve(group, generator, NULL) <= 0) {
        ERROR_MSG("EC_POINT_is_on_curve ERROR\n");
        goto error;
    }

	BN_hex2bn(&cofactor, in_cf);
	if (!EC_GROUP_set_generator(group, generator, order, cofactor)) {
        ERROR_MSG("EC_GROUP_set_generator ERROR\n");
        goto error;
    }

#ifdef SHOW_DEBUG_PUB
	DEBUG_MSG("Chinese SM2 ec curve (%s) attribites are:\n",
            is_prime ? "Fp" : "F2m");
    DEBUG_MSG("degree is %d\n", EC_GROUP_get_degree(group));
    PrintBN(p);
    PrintBN(a);
    PrintBN(b);
    PrintBN(order);
    PrintBN(cofactor);
    DEBUG_MSG(" -- Generator:\n");
    PrintBN(Gx);
    PrintBN(Gy);
#endif

    ret = 1;
error:
    BN_free(p);
    BN_free(a);
    BN_free(b);
	EC_POINT_free(generator);
    BN_free(Gx);
    BN_free(Gy);
    BN_free(order);
    BN_free(cofactor);
    if (!ret) {
        EC_GROUP_free(group);
        group = NULL;
    }

    return group;
}

/* used in sm2 test */
EC_KEY *sm2_create_eckey(const EC_GROUP *group, const char *in_pri,
        const char *in_pubx, const char *in_puby)
{
	EC_KEY *eckey = NULL;
    BIGNUM *pri = NULL;
    BIGNUM *x = NULL, *y = NULL;
    EC_POINT *pub = NULL;
    int ret = -1, is_prime;

    is_prime = (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) 
            == NID_X9_62_prime_field);

    eckey = EC_KEY_new();
    if (!eckey) {
        ERROR_MSG("EC_KEY_new ERROR\n");
        goto error;
    }

    if (!EC_KEY_set_group(eckey, group)) {
        ERROR_MSG("EC_KEY_set_group ERROR\n");
        goto error;
    }

    x = BN_new();
    y = BN_new();
    if (!x || !y) {
        ERROR_MSG("BN_new ERROR\n");
        goto error;
    }

    pri = BN_new();
	BN_hex2bn(&pri, in_pri);
    BN_hex2bn(&x, in_pubx);
    BN_hex2bn(&y, in_puby);
    pub = EC_POINT_new(group);

    if (is_prime) {
        if (!EC_POINT_set_affine_coordinates_GFp(group, pub, x, y, NULL)) {
            ERROR_MSG("EC_POINT_set_affine_coordinates_GFp ERROR\n");
            goto error;
        }
    } else {
# ifndef OPENSSL_NO_EC2M
        if (!EC_POINT_set_affine_coordinates_GF2m(group, pub, x, y, NULL)) {
            ERROR_MSG("EC_POINT_set_affine_coordinates_GFp ERROR\n");
            goto error;
        }
# else
        ERROR_MSG("OPENSSL_NO_EC2M ERROR\n");
        goto error;
# endif
    }

    if (!EC_KEY_set_private_key(eckey, pri)) {
        ERROR_MSG("EC_KEY_set_private_key ERROR\n");
        goto error;
    }
    if (!EC_KEY_set_public_key(eckey, pub)) {
        ERROR_MSG("EC_KEY_set_public_key ERROR\n");
        goto error;
    }
    if (!EC_KEY_check_key(eckey)) {
        ERROR_MSG("EC_KEY_check_key ERROR\n");
        goto error;
    }

#ifdef SHOW_DEBUG_PUB
    DEBUG_MSG("Private Key:\n");
    PrintBN(pri);
    DEBUG_MSG("Public Key:\n");
    PrintBN(x);
    PrintBN(y);
#endif

    ret = 0;
error:
    if (pri) BN_free(pri);
    if (x) BN_free(x);
    if (y) BN_free(y);
    if (pub) EC_POINT_free(pub);
    if (ret) {
        if (eckey) EC_KEY_free(eckey);
        eckey = NULL;
    }

    return eckey;
}

#define ECDH_KDF_MAX    (1 << 30)

int myECDH_KDF_X9_62(unsigned char *out, size_t outlen, 
        const unsigned char *Z, size_t Zlen,
        const unsigned char *sinfo, size_t sinfolen,
        const EVP_MD *md)
{
    EVP_MD_CTX mctx;
    int rv = 0;
    unsigned int i;
    size_t mdlen;
    unsigned char ctr[4];

    if (sinfolen > ECDH_KDF_MAX || outlen > ECDH_KDF_MAX 
            || Zlen > ECDH_KDF_MAX)
        return 0;
    mdlen = EVP_MD_size(md);
    EVP_MD_CTX_init(&mctx);
    for (i = 1;; i++) {
        unsigned char mtmp[EVP_MAX_MD_SIZE];
        EVP_DigestInit_ex(&mctx, md, NULL);
        ctr[3] = i & 0xFF;
        ctr[2] = (i >> 8) & 0xFF;
        ctr[1] = (i >> 16) & 0xFF;
        ctr[0] = (i >> 24) & 0xFF;
        if (!EVP_DigestUpdate(&mctx, Z, Zlen))
            goto err;
        if (!EVP_DigestUpdate(&mctx, ctr, sizeof(ctr)))
            goto err;
        if (!EVP_DigestUpdate(&mctx, sinfo, sinfolen))
            goto err;
        if (outlen >= mdlen) {
            if (!EVP_DigestFinal(&mctx, out, NULL))
                goto err;
            outlen -= mdlen;
            if (outlen == 0)
            break;
            out += mdlen;
        } else {
            if (!EVP_DigestFinal(&mctx, mtmp, NULL))
            goto err;
            memcpy(out, mtmp, outlen);
            OPENSSL_cleanse(mtmp, mdlen);
            break;
        }
    }
    rv = 1;
err:
    EVP_MD_CTX_cleanup(&mctx);
    return rv;
}

