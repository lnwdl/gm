/* Copyright (C) lnwdl (lnwdl@163.com)
 * All rights reserved.
 *
 * SM2 ecies.
 */

#include <stdio.h>
#include <string.h>
#include "public.h"
#include "evp_sm3.h"
#include "ech_sm2.h"
#include "ece_sm2.h"

unsigned char *sm2_encrypt(const unsigned char *in, const size_t ilen,
        EC_KEY *eckey,          /* local private key */
        const BIGNUM *l_rnd,    /* local random */
        const EC_POINT *r_pub,  /* remote public key */
        size_t *olen)           /* out length */
{
	const EC_GROUP *group = NULL;
    BIGNUM *order = NULL, *x = NULL, *y = NULL, *rnd = NULL;
    EC_POINT *C1_point = NULL, *kP = NULL;
    const EVP_MD *md = EVP_sm3();
    EVP_MD_CTX mctx;
    unsigned char *buf = NULL, *t = NULL, *C1 = NULL, *C2 = NULL, *out = NULL;
    unsigned char C3[EVP_MAX_MD_SIZE];
    size_t i, xlen, ylen, C1len, C2len, C3len, blen;
    point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;
    int ret = 0, is_prime, degree;

    if (!in || !olen || !eckey || !r_pub) {
        ERROR_MSG("parameters ERROR\n");
        goto error;
    }

    group = EC_KEY_get0_group(eckey);
    if (!group) {
        ERROR_MSG("EC_KEY_get0_group ERROR\n");
        goto error;
    }

    is_prime = (EC_METHOD_get_field_type(EC_GROUP_method_of(group))
            == NID_X9_62_prime_field);
    degree = EC_GROUP_get_degree(group);

    /* check remote public key */
    if (EC_POINT_is_at_infinity(group, r_pub)) {
        ERROR_MSG("EC_POINT_is_at_infinity ERROR\n");
        goto error;
    }

    if (EC_POINT_is_on_curve(group, r_pub, NULL) <= 0) {
        ERROR_MSG("EC_POINT_is_on_curve ERROR\n");
        goto error;
    }

    x = BN_new();
    y = BN_new();
    if (!x || !y) {
        ERROR_MSG("BN_new ERROR\n");
        goto error;
    }

#ifdef SHOW_DEBUG_ECE
    if (is_prime) {
        if (!EC_POINT_get_affine_coordinates_GFp(group, r_pub,
                    x, y, NULL)) {
            ERROR_MSG("EC_POINT_get_affine_coordinates_GFp ERROR\n");
            goto error;
        }
    } else {
# ifndef OPENSSL_NO_EC2M
        if (!EC_POINT_get_affine_coordinates_GF2m(group, r_pub,
                    x, y, NULL)) {
            ERROR_MSG("EC_POINT_get_affine_coordinates_GF2m ERROR\n");
            goto error;
        }
# else
        ERROR_MSG("OPENSSL_NO_EC2M ERROR\n");
        goto error;
# endif
    }

	DEBUG_MSG("r_pub:\n");
	PrintBN(x);
	PrintBN(y);
#endif

    /* deal with random */
    if (!l_rnd) { /* generate a new random */
        rnd = BN_new();
        order = BN_new();
        if (!rnd || !order) {
            ERROR_MSG("BN_new ERROR\n");
            goto error;
        }

        if (!EC_GROUP_get_order(group, order, NULL)) {
            ERROR_MSG("EC_GROUP_get_order ERROR\n");
            goto error;
        }

        do {
            if (!BN_rand_range(rnd, order)) {
                ERROR_MSG("BN_rand_range ERROR\n");
                goto error;
            }
        } while (BN_is_zero(rnd));
    } else { /* use the old random */
        rnd = BN_dup(l_rnd);
    }

#ifdef SHOW_DEBUG_ECE
    PrintBN(rnd);
#endif

    C1_point = EC_POINT_new(group);
    if (!C1_point) {
        ERROR_MSG("EC_POINT_new ERROR\n");
        goto error;
    }
    if (!EC_POINT_mul(group, C1_point, rnd, NULL, NULL, NULL)) {
        ERROR_MSG("EC_POINT_mul ERROR\n");
        goto error;
    }
	if (!EC_POINT_get_affine_coordinates_GFp(group, C1_point, x, y, NULL)) {
        ERROR_MSG("EC_POINT_get_affine_coordinates_GFp ERROR\n");
        goto error;
    }

#ifdef SHOW_DEBUG_ECE
	DEBUG_MSG("C1_point:\n");
	PrintBN(x);
	PrintBN(y);
#endif

    C1len = EC_POINT_point2oct(group, C1_point, form, NULL, 0, NULL);
    if (!C1len) {
        ERROR_MSG("EC_POINT_point2oct 1 ERROR\n");
        goto error;
    }

    C1 = OPENSSL_malloc(C1len * sizeof (unsigned char));
    if (!C1) {
        ERROR_MSG("OPENSSL_malloc ERROR\n");
        goto error;
    }

    if (!EC_POINT_point2oct(group, C1_point, form, C1, C1len, NULL)) {
        ERROR_MSG("EC_POINT_point2oct 2 ERROR\n");
        goto error;
    }

#ifdef SHOW_DEBUG_ECE
    DEBUG_MSG("C1\n");
    ShwHexBuf(C1, C1len);
#endif

    kP = EC_POINT_new(group);
    if (!kP) {
        ERROR_MSG("EC_POINT_new ERROR\n");
        goto error;
    }
    if (!EC_POINT_mul(group, kP, NULL, r_pub, rnd, NULL)) {
        ERROR_MSG("EC_POINT_mul ERROR\n");
        goto error;
    }

    if (is_prime) {
        if (!EC_POINT_get_affine_coordinates_GFp(group, kP,
                    x, y, NULL)) {
            ERROR_MSG("EC_POINT_get_affine_coordinates_GFp ERROR\n");
            goto error;
        }
    } else {
# ifndef OPENSSL_NO_EC2M
        if (!EC_POINT_get_affine_coordinates_GF2m(group, kP,
                    x, y, NULL)) {
            ERROR_MSG("EC_POINT_get_affine_coordinates_GF2m ERROR\n");
            goto error;
        }
# else
        ERROR_MSG("OPENSSL_NO_EC2M ERROR\n");
        goto error;
# endif
    }

#ifdef SHOW_DEBUG_ECE
	DEBUG_MSG("kP:\n");
	PrintBN(x);
	PrintBN(y);
#endif

    C2len = ilen;
    t = OPENSSL_malloc(C2len * sizeof (unsigned char));
    C2 = OPENSSL_malloc(C2len * sizeof (unsigned char));
    xlen = ylen = (degree + 7) / 8;
    blen = xlen + ylen;
    buf = OPENSSL_malloc(blen * sizeof (unsigned char));
    if (!t || !C2 || !buf) {
        ERROR_MSG("OPENSSL_malloc ERROR\n");
        goto error;
    }

    /* x || y */
    if (!BN_bn2bin_gm(x, buf, degree)
            || !BN_bn2bin_gm(y, buf + xlen, degree)) {
        ERROR_MSG("BN_bn2bin_gm ERROR\n");
        goto error;
    }

#ifdef SHOW_DEBUG_ECE
	DEBUG_MSG("KDF input is:\n");
    ShwHexBuf(buf, blen);
#endif

    if (!myECDH_KDF_X9_62(t, C2len, buf, blen, NULL, 0, md)) {
        ERROR_MSG("myECDH_KDF_X9_62 ERROR\n");
        goto error;
    }

#ifdef SHOW_DEBUG_ECE
	DEBUG_MSG("KDF compute Share Key is:\n");
    ShwHexBuf(t, C2len);
#endif

    /* do encrypt use cipher t */
    for (i = 0; i < C2len; ++i) {
        C2[i] = in[i] ^ t[i];
    }

#ifdef SHOW_DEBUG_ECE
    DEBUG_MSG("C2:\n");
    ShwHexBuf(C2, C2len);
#endif

    /* Hash(x || M || y) */
    blen = sizeof (C3) / sizeof (unsigned char);
    EVP_MD_CTX_init(&mctx);
    EVP_DigestInit(&mctx, md);
    EVP_DigestUpdate(&mctx, buf, xlen); /* x */
    EVP_DigestUpdate(&mctx, (unsigned char *)in, ilen);
    EVP_DigestUpdate(&mctx, buf + xlen, ylen); /* y */
    EVP_DigestFinal(&mctx, C3, &blen);
    C3len = blen;

#ifdef SHOW_DEBUG_ECE
    DEBUG_MSG("C3:\n");
    ShwHexBuf(C3, C3len);
#endif

    blen = C1len + C2len + C3len;
    out = OPENSSL_malloc(blen * sizeof (unsigned char));
    if (!out) {
        ERROR_MSG("OPENSSL_malloc ERROR\n");
        goto error;
    }

    /* C1 || C3 || C2 */
    memcpy(out, C1, C1len);
    memcpy(out + C1len, C3, C3len);
    memcpy(out + C1len + C3len, C2, C2len);

    *olen = blen;

    ret = 1;
error:
    if (x) BN_free(x);
    if (y) BN_free(y);
    if (rnd) BN_free(rnd);
    if (order) BN_free(order);
    if (C1_point) EC_POINT_free(C1_point);
    if (C1) OPENSSL_free(C1);
    if (kP) EC_POINT_free(kP);
    if (buf) OPENSSL_free(buf);
    if (t) OPENSSL_free(t);
    if (C2) OPENSSL_free(C2);
    EVP_MD_CTX_cleanup(&mctx);
    if (!ret) {
        if (out) OPENSSL_free(out);
        out = NULL;
    }

	return out;
}

unsigned char *sm2_decrypt(const unsigned char *in, const size_t ilen,
        EC_KEY *eckey,          /* local private key */
        size_t *olen)           /* out length */
{
    const EC_GROUP *group;
    const EC_POINT *pub;
    EC_POINT *C1_point = NULL, *dC = NULL;
    const BIGNUM *pri;
    BIGNUM *x = NULL, *y = NULL;
    size_t i, C1len, C2len, C3len, xlen, ylen, blen;
    const EVP_MD *md = EVP_sm3();
    EVP_MD_CTX mctx;
    point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;
    const unsigned char *C1, *C2, *C3;
    unsigned char *buf = NULL, *t = NULL, *M = NULL;
    unsigned char u[EVP_MAX_MD_SIZE];
    int ret = 0, is_prime, degree;

    if (!in || !eckey || !olen) {
        ERROR_MSG("parameters ERROR\n");
        goto error;
    }

    group = EC_KEY_get0_group(eckey);
    if (!group) {
        ERROR_MSG("EC_KEY_get0_group ERROR\n");
        goto error;
    }

    is_prime = (EC_METHOD_get_field_type(EC_GROUP_method_of(group))
            == NID_X9_62_prime_field);
    degree = EC_GROUP_get_degree(group);

    pub = EC_KEY_get0_public_key(eckey);
    if (!pub) {
        ERROR_MSG("EC_KEY_get0_public_key ERROR\n");
        goto error;
    }

    C1len = EC_POINT_point2oct(group, pub, form, NULL, 0, NULL);
    if (!C1len) {
        ERROR_MSG("EC_POINT_point2oct 1 ERROR\n");
        goto error;
    }

    if (ilen < C1len) {
        ERROR_MSG("input len is little then C1len\n");
        goto error;
    }
    C1 = in;

    C1_point = EC_POINT_new(group);
    if (!C1_point) {
        ERROR_MSG("EC_POINT_new ERROR\n");
        goto error;
    }
    if (!EC_POINT_oct2point(group, C1_point, C1, C1len, NULL)) {
        ERROR_MSG("EC_POINT_oct2point ERROR\n");
        goto error;
    }

    /* check C1_point */
    if (EC_POINT_is_at_infinity(group, C1_point)) {
        ERROR_MSG("EC_POINT_is_at_infinity ERROR\n");
        goto error;
    }

    if (EC_POINT_is_on_curve(group, C1_point, NULL) <= 0) {
        ERROR_MSG("EC_POINT_is_on_curve ERROR\n");
        goto error;
    }

    x = BN_new();
    y = BN_new();
    if (!x || !y) {
        ERROR_MSG("BN_new ERROR\n");
        goto error;
    }

#ifdef SHOW_DEBUG_ECE
    if (is_prime) {
        if (!EC_POINT_get_affine_coordinates_GFp(group, C1_point,
                    x, y, NULL)) {
            ERROR_MSG("EC_POINT_get_affine_coordinates_GFp ERROR\n");
            goto error;
        }
    } else {
# ifndef OPENSSL_NO_EC2M
        if (!EC_POINT_get_affine_coordinates_GF2m(group, C1_point,
                    x, y, NULL)) {
            ERROR_MSG("EC_POINT_get_affine_coordinates_GF2m ERROR\n");
            goto error;
        }
# else
        ERROR_MSG("OPENSSL_NO_EC2M ERROR\n");
        goto error;
# endif
    }

	DEBUG_MSG("C1_point:\n");
	PrintBN(x);
	PrintBN(y);
#endif

    pri = EC_KEY_get0_private_key(eckey);
    if (!pri) {
        ERROR_MSG("EC_KEY_get0_private_key ERROR\n");
        goto error;
    }

    dC = EC_POINT_new(group);
    if (!dC) {
        ERROR_MSG("EC_POINT_new ERROR\n");
        goto error;
    }

    /* compute dC */
    if (!EC_POINT_mul(group, dC, NULL, C1_point, pri, NULL)) {
        ERROR_MSG("EC_POINT_new ERROR\n");
        goto error;
    }

    if (is_prime) {
        if (!EC_POINT_get_affine_coordinates_GFp(group, dC,
                    x, y, NULL)) {
            ERROR_MSG("EC_POINT_get_affine_coordinates_GFp ERROR\n");
            goto error;
        }
    } else {
# ifndef OPENSSL_NO_EC2M
        if (!EC_POINT_get_affine_coordinates_GF2m(group, dC,
                    x, y, NULL)) {
            ERROR_MSG("EC_POINT_get_affine_coordinates_GF2m ERROR\n");
            goto error;
        }
# else
        ERROR_MSG("OPENSSL_NO_EC2M ERROR\n");
        goto error;
# endif
    }

#ifdef SHOW_DEBUG_ECE
	DEBUG_MSG("dC:\n");
	PrintBN(x);
	PrintBN(y);
#endif

    xlen = ylen = (degree + 7) / 8;
    blen = xlen + ylen;
    /* calculate the kdf output length */
    C3len = EVP_MD_size(md);
    if (ilen < C1len + C3len) {
        ERROR_MSG("input len is little then C1len + C3len\n");
        goto error;
    }
    C3 = C1 + C1len;
    C2len = ilen - C1len - C3len;
    C2 = C3 + C3len;

    buf = OPENSSL_malloc(blen * sizeof (unsigned char));
    t = OPENSSL_malloc(C2len * sizeof (unsigned char));
    M = OPENSSL_malloc(C2len * sizeof (unsigned char));
    if (!buf || !t || !M) {
        ERROR_MSG("OPENSSL_malloc ERROR\n");
        goto error;
    }

    /* x || y */
    if (!BN_bn2bin_gm(x, buf, degree)
            || !BN_bn2bin_gm(y, buf + xlen, degree)) {
        ERROR_MSG("BN_bn2bin ERROR\n");
        goto error;
    }

#ifdef SHOW_DEBUG_ECE
	DEBUG_MSG("KDF input: \n");
    ShwHexBuf(buf, blen);
#endif

    if (!myECDH_KDF_X9_62(t, C2len, buf, blen, NULL, 0, md)) {
        ERROR_MSG("myECDH_KDF_X9_62 ERROR\n");
        goto error;
    }

#ifdef SHOW_DEBUG_ECE
	DEBUG_MSG("KDF compute Share Key is:\n");
    ShwHexBuf(t, C2len);
#endif

    /* do decrypt using the cipher t */
    for (i = 0; i < C2len; ++i) {
        M[i] = C2[i] ^ t[i];
    }

#ifdef SHOW_DEBUG_ECE
    DEBUG_MSG("M:\n");
    ShwHexBuf(M, C2len);
#endif

    /* Hash(x || M || y) */
    blen = sizeof (u) / sizeof (unsigned char);
    EVP_MD_CTX_init(&mctx);
    EVP_DigestInit(&mctx, md);
    EVP_DigestUpdate(&mctx, buf, xlen); /* x */
    EVP_DigestUpdate(&mctx, M, C2len);
    EVP_DigestUpdate(&mctx, buf + xlen, ylen); /* y */
    EVP_DigestFinal(&mctx, u, &blen);

    if (blen != C3len || memcmp(u, C3, blen)) {
        ERROR_MSG("compare hash ERROR\n");
        goto error;
    }

    *olen = C2len;

    ret = 1;
error:
    if (C1_point) EC_POINT_free(C1_point);
    if (x) BN_free(x);
    if (y) BN_free(y);
    if (dC) EC_POINT_free(dC);
    if (buf) OPENSSL_free(buf);
    if (t) OPENSSL_free(t);
    if (!ret) {
        if (M) OPENSSL_free(M);
        M = NULL;
    }

    return M;
}

/* ==================== test begin ========================= */

/* the input data and results are comming from 
 * GM/T 0003.4-2012 A.2
 * */
static char *fp_p  =
"bdb6f4fe3e8b1d9e0da8c0d46f4c318cefe4afe3b6b8551f";
static char *fp_a  =
"bb8e5e8fbc115e139fe6a814fe48aaa6f0ada1aa5df91985";
static char *fp_b  =
"1854bebdc31b21b7aefc80ab0ecd10d5b1b3308e6dbf11c1";
static char *fp_gx =
"4ad5f7048de709ad51236de65e4d4b482c836dc6e4106640";
static char *fp_gy =
"02bb3a02d4aaadacae24817a4ca3a1b014b5270432db27d2";
static char *fp_o  =
"bdb6f4fe3e8b1d9e0da8c0d40fc962195dfae76f56564677";
static char *fp_cf ="1";

static char *fp_pri  =
"58892b807074f53fbf67288a1dfaa1ac313455fe60355afd";
static char *fp_pubx =
"79f0a9547ac6d100531508b30d30a56536bcfc8149f4af4a";
static char *fp_puby =
"ae38f2d8890838df9c19935a65a8bcc8994bc7924672f912";
static char *fp_rnd = 
"384f30353073aeece7a1654330a96204d37982a3e15b2cb5";

static char *fp_m = "encryption standard";

static unsigned char fp_ret[] = {
    0x04, 0x23, 0xfc, 0x68, 0x0b, 0x12, 0x42, 0x94, 
    0xdf, 0xdf, 0x34, 0xdb, 0xe7, 0x6e, 0x0c, 0x38, 
    0xd8, 0x83, 0xde, 0x4d, 0x41, 0xfa, 0x0d, 0x4c, 
    0xf5, 0x70, 0xcf, 0x14, 0xf2, 0x0d, 0xaf, 0x0c, 
    0x4d, 0x77, 0x7f, 0x73, 0x8d, 0x16, 0xb1, 0x68, 
    0x24, 0xd3, 0x1e, 0xef, 0xb9, 0xde, 0x31, 0xee, 
    0x1f, 0x6a, 0xfb, 0x3b, 0xce, 0xbd, 0x76, 0xf8, 
    0x2b, 0x25, 0x2c, 0xe5, 0xeb, 0x25, 0xb5, 0x79, 
    0x96, 0x86, 0x90, 0x2b, 0x8c, 0xf2, 0xfd, 0x87, 
    0x53, 0x6e, 0x55, 0xef, 0x76, 0x03, 0xb0, 0x9e, 
    0x7c, 0x61, 0x05, 0x67, 0xdb, 0xd4, 0x85, 0x4f, 
    0x51, 0xf4, 0xf0, 0x0a, 0xdc, 0xc0, 0x1c, 0xfe, 
    0x90, 0xb1, 0xfb, 0x1c
};

static int sm2_ecies_test_fp(const int idx)
{
    EC_GROUP *group = NULL;
    EC_KEY *eckey = NULL;
    const EC_POINT *r_pub;
    BIGNUM *rnd = NULL;
    unsigned char *enc = NULL, *dec = NULL;
    size_t mlen, elen, dlen;

    group = sm2_create_group(EC_GFp_simple_method(),
            fp_p, fp_a, fp_b, fp_gx, fp_gy, fp_o, fp_cf); 
    if (!group) {
        ERROR_MSG("sm2_create_group ERROR\n");
        goto error;
    }

#ifdef SHOW_DEBUG_ECE
    DEBUG_MSG("User eckey\n");
#endif
    eckey = sm2_create_eckey(group, fp_pri, fp_pubx, fp_puby);
    if (!eckey) {
        ERROR_MSG("sm2_create_eckey ERROR\n");
        goto error;
    }

    /* set random */
    if (!(rnd = BN_new()) || !BN_hex2bn(&rnd, fp_rnd)) {
        ERROR_MSG("BN_hex2bn ERROR\n");
        goto error;
    }

    r_pub = EC_KEY_get0_public_key(eckey);
    if (!r_pub) {
        ERROR_MSG("EC_KEY_get0_public_key ERROR\n");
        goto error;
    }

    mlen = strlen(fp_m);
    enc = sm2_encrypt((unsigned char *)fp_m, mlen, eckey, rnd, r_pub, &elen);
    if (!enc) {
        ERROR_MSG("sm2_encrypt ERROR\n");
        goto error;
    }

#ifdef SHOW_DEBUG_ECE
    DEBUG_MSG("encrypt msg:\n");
    ShwHexBuf(enc, elen);
#endif

    if (elen != sizeof (fp_ret) || memcmp(enc, fp_ret, elen)) {
        ERROR_MSG("%s ----------> testcase[%d] ERROR\n", __FUNCTION__, idx);
        goto error;
    }

    dec = sm2_decrypt(enc, elen, eckey, &dlen);
    if (!dec) {
        ERROR_MSG("sm2_decrypt ERROR\n");
        goto error;
    }

    if (mlen != dlen || memcmp(fp_m, dec, mlen)) {
        ERROR_MSG("%s ----------> testcase[%d] ERROR\n", __FUNCTION__, idx);
        goto error;
    }

    printf("%s ----------> testcase[%d] ok\n", __FUNCTION__, idx);
error:
    if (group) EC_GROUP_free(group);
    if (eckey) EC_KEY_free(eckey);
    if (rnd) BN_free(rnd);
    if (enc) OPENSSL_free(enc);
    if (dec) OPENSSL_free(dec);

    return 0;
}

# ifndef OPENSSL_NO_EC2M
/* the input data and results are comming from 
 * GM/T 0003.4-2012 A.3
 * */
static char *f2m_p  =
"02000000000000000000000000000000000000000000008001";
static char *f2m_a  = "0";
static char *f2m_b  =
"002fe22037b624dbebc4c618e13fd998b1a18e1ee0d05c46fb";
static char *f2m_gx =
"d78d47e85c93644071bc1c212cf994e4d21293aad8060a84";
static char *f2m_gy =
"615b9e98a31b7b2fddeeecb76b5d875586293725f9d2fc0c";
static char *f2m_o  =
"80000000000000000000000043e9885c46bf45d8c5ebf3a1";
static char *f2m_cf ="1";

static char *f2m_pri  =
"6c205c1589087376c2fe5feee153d4ac875d643eb8caf6c5";
static char *f2m_pubx =
"00e788f191c5591636fa992ce67cdc8d3b16e4f4d46af267b8";
static char *f2m_puby =
"00bd6e7e5e4113d79020ed5a10287c14b7a6767c4d814adbfd";
static char *f2m_rnd = 
"6e51c5373d5b4705dc9b94fa9bcf30a737ed8d691e76d9f0";

static char *f2m_m = "encryption standard";

static unsigned char f2m_ret[] = {
    0x04, 0x00, 0x95, 0xa8, 0xb8, 0x66, 0x7a, 0xcf, 
    0x09, 0x7f, 0x65, 0xce, 0x96, 0xeb, 0xfe, 0x53, 
    0x42, 0x2f, 0xcf, 0x15, 0x87, 0x6d, 0x16, 0x44, 
    0x6b, 0x8a, 0x01, 0x7a, 0x1e, 0xc7, 0xc9, 0xba, 
    0xb0, 0xde, 0x07, 0x05, 0x22, 0x31, 0x1e, 0x75, 
    0xcd, 0x31, 0xc3, 0xc4, 0xd7, 0x41, 0x50, 0xe8, 
    0x4e, 0x0a, 0x95, 0xf0, 0xa4, 0x1f, 0x6f, 0x48, 
    0xac, 0x72, 0x3c, 0xec, 0xfc, 0x4b, 0x76, 0x72, 
    0x99, 0xa5, 0xe2, 0x5c, 0x06, 0x41, 0x67, 0x9f, 
    0xbd, 0x2d, 0x4d, 0x20, 0xe9, 0xff, 0xd5, 0xb9, 
    0xf0, 0xda, 0xb8, 0xd9, 0x31, 0x6e, 0x22, 0x8b, 
    0xc2, 0xc8, 0x9b, 0xb3, 0x5e, 0x07, 0x78, 0xde, 
    0x33, 0x27, 0x5f, 0xeb, 0x15, 0xc0
};

static int sm2_ecies_test_f2m(const int idx)
{
    EC_GROUP *group = NULL;
    EC_KEY *eckey = NULL;
    const EC_POINT *r_pub;
    BIGNUM *rnd = NULL;
    unsigned char *enc = NULL, *dec = NULL;
    size_t mlen, elen, dlen;

    group = sm2_create_group(EC_GF2m_simple_method(),
            f2m_p, f2m_a, f2m_b, f2m_gx, f2m_gy, f2m_o, f2m_cf);
    if (!group) {
        ERROR_MSG("sm2_create_group ERROR\n");
        goto error;
    }

#ifdef SHOW_DEBUG_ECE
    DEBUG_MSG("User eckey\n");
#endif
    eckey = sm2_create_eckey(group, f2m_pri, f2m_pubx, f2m_puby);
    if (!eckey) {
        ERROR_MSG("sm2_create_eckey ERROR\n");
        goto error;
    }

    /* set random */
    if (!(rnd = BN_new()) || !BN_hex2bn(&rnd, f2m_rnd)) {
        ERROR_MSG("BN_hex2bn ERROR\n");
        goto error;
    }

    r_pub = EC_KEY_get0_public_key(eckey);
    if (!r_pub) {
        ERROR_MSG("EC_KEY_get0_public_key ERROR\n");
        goto error;
    }

    mlen = strlen(f2m_m);
    enc = sm2_encrypt((unsigned char *)f2m_m, mlen, eckey, rnd, r_pub, &elen);
    if (!enc) {
        ERROR_MSG("sm2_encrypt ERROR\n");
        goto error;
    }

#ifdef SHOW_DEBUG_ECE
    DEBUG_MSG("encrypt msg:\n");
    ShwHexBuf(enc, elen);
#endif

    if (elen != sizeof (f2m_ret) || memcmp(enc, f2m_ret, elen)) {
        ERROR_MSG("%s ----------> testcase[%d] ERROR\n", __FUNCTION__, idx);
        goto error;
    }

    dec = sm2_decrypt(enc, elen, eckey, &dlen);
    if (!dec) {
        ERROR_MSG("sm2_decrypt ERROR\n");
        goto error;
    }

    if (mlen != dlen || memcmp(f2m_m, dec, mlen)) {
        ERROR_MSG("%s ----------> testcase[%d] ERROR\n", __FUNCTION__, idx);
        goto error;
    }

    printf("%s ----------> testcase[%d] ok\n", __FUNCTION__, idx);
error:
    if (group) EC_GROUP_free(group);
    if (eckey) EC_KEY_free(eckey);
    if (rnd) BN_free(rnd);
    if (enc) OPENSSL_free(enc);
    if (dec) OPENSSL_free(dec);

    return 0;
}
# endif

int sm2_ecies_test(int argc, char *argv[])
{
    sm2_ecies_test_fp(1);
# ifndef OPENSSL_NO_EC2M
    sm2_ecies_test_f2m(2);
# endif

    return 0;
}

