/* Copyright (C) lnwdl (lnwdl@163.com)
 * All rights reserved.
 *
 * SM2 ECDSA_METHOD.
 */

#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include "public.h"
#include "evp_sm3.h"
#include "ecs_sm2.h"

/* the @r is always computed by the @k */
static int sm2dsa_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kp,
        BIGNUM **rp)
{
    const EC_GROUP *group;
    BN_CTX *ctx = NULL;
    BIGNUM *k = NULL, *r = NULL, *order = NULL, *X = NULL;
    EC_POINT *tmp_point = NULL;
    int ret = 0, is_prime;

    if (!eckey || !(group = EC_KEY_get0_group(eckey))) {
        ERROR_MSG("ECKEY_get0_group ERROR\n");
        goto error;
    }

    is_prime = (EC_METHOD_get_field_type(EC_GROUP_method_of(group))
                == NID_X9_62_prime_field);

    if (!ctx_in) {
        if (!(ctx = BN_CTX_new())) {
            ERROR_MSG("BN_CTX_new ERROR\n");
            goto error;
        }
    } else {
        ctx = ctx_in;
    }

    k = BN_new();       /* returned in *kp */
    r = BN_new();       /* returned in *rp */
    order = BN_new();
    X = BN_new();
    if (!k || !r || !order || !X) {
        ERROR_MSG("BN_new ERROR\n");
        goto error;
    }

    if (!(tmp_point = EC_POINT_new(group))) {
        ERROR_MSG("EC_POINT_new ERROR\n");
        goto error;
    }

    if (!EC_GROUP_get_order(group, order, ctx)) {
        ERROR_MSG("EC_GROUP_get_order ERROR\n");
        goto error;
    }

    do {
        if (*kp) { /* use the given random k */
            if (!BN_copy(k, *kp)) {
                ERROR_MSG("BN_copy ERROR\n");
                goto error;
            }
        } else {/* generate new random k */
            do {
                if (!BN_rand_range(k, order)) {
                    ERROR_MSG("BN_rand_range ERROR\n");
                    goto error;
                }
            } while (BN_is_zero(k));

		    /* We do not want timing information to leak the length of k,
		     * so we compute G*k using an equivalent scalar of fixed
		     * bit-length. */
		    if (!BN_add(k, k, order)) {
                ERROR_MSG("BN_add 1 ERROR\n");
                goto error;
            }

            if (BN_num_bits(k) <= BN_num_bits(order)) {
		        if (!BN_add(k, k, order)) {
                    ERROR_MSG("BN_add 2 ERROR\n");
                    goto error;
                }
            }
        }

		/* compute r the x-coordinate of (generator * k) */
		if (!EC_POINT_mul(group, tmp_point, k, NULL, NULL, ctx)) {
            ERROR_MSG("EC_POINT_mul ERROR\n");
			goto error;
		}

        if (is_prime) {
            if (!EC_POINT_get_affine_coordinates_GFp(group,
                        tmp_point, X, NULL, ctx)) {
                ERROR_MSG("EC_POINT_get_affine_coordinates_GFp ERROR\n");
                goto error;
            }
        } else {
# ifndef OPENSSL_NO_EC2M
            if (!EC_POINT_get_affine_coordinates_GF2m(group,
                        tmp_point, X, NULL, ctx)) {
                ERROR_MSG("EC_POINT_get_affine_coordinates_GF2m ERROR\n");
                goto error;
            }
# else
            ERROR_MSG("OPENSSL_NO_EC2M ERROR\n");
            goto error;
# endif
        }

        if (!BN_nnmod(r, X, order, ctx)) {
            ERROR_MSG("BN_nnmod ERROR\n");
            goto error;
        }
    } while (BN_is_zero(r));

    /* clear old values if necessary */
    if (*rp) BN_clear_free(*rp);
    if (*kp) BN_clear_free(*kp);

    /* save the pre-computed values */
    *rp = r;
    *kp = k;

    ret = 1;
error:
    if (!ret) {
        if (k) BN_clear_free(k);
        if (r) BN_clear_free(r);
    }
    if (!ctx_in && ctx) BN_CTX_free(ctx);
    if (order) BN_free(order);
    if (tmp_point) EC_POINT_free(tmp_point);
    if (X) BN_clear_free(X);

    return ret;
}

static int getE(EC_KEY *eckey, const unsigned char *in, const size_t ilen, 
        unsigned char *out, size_t *olen) 
{
    const EC_POINT *pub;
    unsigned char Za[EVP_MAX_MD_SIZE]; 
    size_t Zalen;
    EVP_MD_CTX ctx;
    const EVP_MD *md = EVP_sm3();
    char *ID;

    if (!eckey || !in || !out) {
        return 0;
    }

    pub = EC_KEY_get0_public_key(eckey);
    if (!pub) {
        return 0;
    }

    ID = getDefID();
    Zalen = sizeof (Za);
    if (!getUserExtInfo(eckey, pub, md, 
                (unsigned char *)ID, strlen(ID), Za, &Zalen)) {
        return 0;
    }

#ifdef SHOW_DEBUG_ECS
    DEBUG_MSG("Za info is:\n");
    ShwHexBuf(Za, Zalen);
#endif

    /* Hash(Za || M) */
    EVP_MD_CTX_init(&ctx);
    EVP_DigestInit(&ctx, md);

    if (!EVP_DigestUpdate(&ctx, Za, Zalen)) {
        return 0;
    }

    if (!EVP_DigestUpdate(&ctx, in, ilen)) {
        return 0;
    }

    if (!EVP_DigestFinal(&ctx, out, olen)) {
        return 0;
    }

    EVP_MD_CTX_cleanup(&ctx);

    return 1;
}

/* the parameter @in is the rawdata needed to sign, not the digested value
 * of the rawdata, this conflicts with OpenSSL sign/verify structure.
 */
static ECDSA_SIG *sm2dsa_do_sign(const unsigned char *in, int ilen,
        const BIGNUM *in_k,     /* input random */
        const BIGNUM *in_r,
        EC_KEY *eckey)
{
	const EC_GROUP *group;
	const BIGNUM *priv_key;
	ECDSA_SIG *ret = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *k = NULL, *bn = NULL, *e = NULL, *order = NULL;
	const BIGNUM *ck;
    unsigned char ebuf[EVP_MAX_MD_SIZE];
    size_t elen;
	int ok = 0, i;

	group = EC_KEY_get0_group(eckey);
	priv_key = EC_KEY_get0_private_key(eckey);
    if (!group || !priv_key) {
        ERROR_MSG("EC_KEY_get0_group/privkey ERROR\n");
		return NULL;
    }

	ret = ECDSA_SIG_new();
	if (!ret) {
        ERROR_MSG("ECDSA_SIG_new ERROR\n");
		return NULL;
	}

    ctx = BN_CTX_new();
    order = BN_new();
    e = BN_new();
    bn = BN_new();
    if (!ctx || !order || !e || !bn) {
        ERROR_MSG("EBN_new ERROR\n");
		goto error;
    }
	if (!EC_GROUP_get_order(group, order, ctx)) {
        ERROR_MSG("EC_GROUP_get_order ERROR\n");
		goto error;
	}
    i = BN_num_bits(order);

    /* compute the e */
    elen = sizeof (ebuf);
    if (!getE(eckey, in, ilen, ebuf, &elen)) {
        ERROR_MSG("getE ERROR\n");
		goto error;
    }

#ifdef SHOW_DEBUG_ECS
    DEBUG_MSG("e is:\n");
    ShwHexBuf(ebuf, elen);
#endif

	/* Need to truncate the tail of ebuf if it is too long */
	if (8 * elen > (size_t)i) {
		elen = (i + 7)/8;
    }
	if (!BN_bin2bn(ebuf, elen, e)) {
        ERROR_MSG("BN_bin2bn ERROR\n");
		goto error;
	}

#ifdef SHOW_DEBUG_ECS
    PrintBN(e);
#endif

    do {
        /* use or compute k and (kG).x */
        if (!in_k || !in_r) {
            if (in_k) {
                k = BN_dup(in_k);
            }

            if (!ECDSA_sign_setup(eckey, ctx, &k, &ret->r)) {
                ERROR_MSG("ECDSA_sign_setup ERROR\n");
                goto error;
            }
            ck = k;
        } else {
            ck = in_k;
            if (!BN_copy(ret->r, in_r)) {
                ERROR_MSG("BN_copy ERROR\n");
                goto error;
            }
        }

#ifdef SHOW_DEBUG_ECS
        BIGNUM *kGx = ret->r;
        PrintBN(ck);
        PrintBN(kGx);
#endif

        /* r = (e + x) mod n */
        if (!BN_mod_add(ret->r, ret->r, e, order, ctx)) {
            ERROR_MSG("BN_mod_add ERROR\n");
            goto error;
        }

        /* check r != 0 && r + ck != 0 */
        if (!BN_mod_add(bn, ret->r, ck, order, ctx)) {
            ERROR_MSG("BN_mod_add ERROR\n");
            goto error;
        }
        if (BN_is_zero(ret->r) || BN_is_zero(bn)) {
            if (in_k && in_r) {
                ERROR_MSG("in_k && in_r ERROR\n");
                goto error;
            } else {
                continue;
            }
        }

#ifdef SHOW_DEBUG_ECS
        PrintBN(ret->r);
#endif

        /* s = ((1 + d)^-1 * (k - r * d)) mod n */
        if (!BN_one(bn)) { /* set bn to 1 */
            ERROR_MSG("BN_one ERROR\n");
            goto error;
        }
        if (!BN_mod_add(ret->s, priv_key, bn, order, ctx)) {
            ERROR_MSG("BN_mod_add ERROR\n");
            goto error;
        }
        /* compute the inverse of s */
        if (!BN_mod_inverse(ret->s, ret->s, order, ctx)) {
            ERROR_MSG("BN_mod_inverse ERROR\n");
            goto error;
        }

#ifdef SHOW_DEBUG_ECS
        BIGNUM *inv_pri_plus_1 = ret->s;
        PrintBN(inv_pri_plus_1);
#endif
        if (!BN_mod_mul(bn, ret->r, priv_key, order, ctx)) {
            ERROR_MSG("BN_mod_mul ERROR\n");
            goto error;
        }
        if (!BN_mod_sub(bn, ck, bn, order, ctx)) {
            ERROR_MSG("BN_mod_sub ERROR\n");
            goto error;
        }
        if (!BN_mod_mul(ret->s, ret->s, bn, order, ctx)) {
            ERROR_MSG("BN_mod_mul ERROR\n");
            goto error;
        }

        /* check s != 0 */
        if (BN_is_zero(ret->s)) {
            if (in_k && in_r) {
                ERROR_MSG("in_k && in_r ERROR\n");
                goto error;
            }
        } else {
            break;
        }
    } while (1);

#ifdef SHOW_DEBUG_ECS
    PrintBN(ret->s);
#endif

    ok = 1;
error:
    if (!ok) {
        ECDSA_SIG_free(ret);
        ret = NULL;
    }
    if (ctx) BN_CTX_free(ctx);
    if (order) BN_free(order);
    if (e) BN_free(e);
    if (bn) BN_free(bn);
    if (k) BN_clear_free(k);

    return ret;
}

/* the parameter @in is the rawdata needed to verify, not the digested value
 * of the rawdata, this conflicts with OpenSSL sign/verify structure.
 */
static int sm2dsa_do_verify(const unsigned char *in, int ilen,
        const ECDSA_SIG *sig, EC_KEY *eckey)
{
	const EC_GROUP *group;
	BN_CTX *ctx;
	BIGNUM *order = NULL, *e = NULL, *t = NULL;
    unsigned char ebuf[EVP_MAX_MD_SIZE];
    size_t elen;
	EC_POINT *point = NULL;
	const EC_POINT *pub_key;
	int ret = -1, i, is_prime;

	/* check input values */
	if (eckey == NULL || (group = EC_KEY_get0_group(eckey)) == NULL ||
	    (pub_key = EC_KEY_get0_public_key(eckey)) == NULL || sig == NULL) {
        ERROR_MSG("parameters ERROR\n");
		return -1;
	}

    is_prime = (EC_METHOD_get_field_type(EC_GROUP_method_of(group))
                == NID_X9_62_prime_field);

    ctx = BN_CTX_new();
    order = BN_new();
    e = BN_new();
    t = BN_new();
    if (!ctx || !order || !e || !t) {
        ERROR_MSG("BN_new ERROR\n");
        goto error;
    }

	if (!EC_GROUP_get_order(group, order, ctx)) {
        ERROR_MSG("EC_GROUP_get_order ERROR\n");
		goto error;
	}

    /* check r, s in [1, n - 1] */
    if (BN_is_zero(sig->r) 
            || BN_is_negative(sig->r) 
            || BN_ucmp(sig->r, order) >= 0 
            || BN_is_zero(sig->s)
            || BN_is_negative(sig->s)
            || BN_ucmp(sig->s, order) >= 0) {
        ERROR_MSG("BN_ucmp ERROR\n");
        ret = 0;
        goto error;
    }

    /* check (t = r + s) mod n != 0 */
    if (!BN_mod_add(t, sig->r, sig->s, order, ctx)) {
        ERROR_MSG("BN_mod_add ERROR\n");
        goto error;
    }
    if (BN_is_zero(t)) {
        ret = 0;
        goto error;
    }

	i = BN_num_bits(order);

    /* compute the e */
    elen = sizeof (ebuf);
    if (!getE(eckey, in, ilen, ebuf, &elen)) {
        ERROR_MSG("getE ERROR\n");
		goto error;
    }

#ifdef SHOW_DEBUG_ECS
    DEBUG_MSG("e is:\n");
    ShwHexBuf(ebuf, elen);
#endif

	/* Need to truncate input if it is too long */
	if (8 * elen > (size_t)i) {
		elen = (i + 7)/8;
    }
	if (!BN_bin2bn(ebuf, elen, e)) {
        ERROR_MSG("BN_bin2bn ERROR\n");
		goto error;
	}

#ifdef SHOW_DEBUG_ECS
    PrintBN(e);
#endif

    /* (x, y) = sG + tP */
    if (!(point = EC_POINT_new(group))) {
        ERROR_MSG("EC_POINT_new ERROR\n");
        goto error;
    }
    if (!EC_POINT_mul(group, point, sig->s, pub_key, t, ctx)) {
        ERROR_MSG("EC_POINT_mul ERROR\n");
        goto error;
    }
    if (is_prime) {
        if (!EC_POINT_get_affine_coordinates_GFp(group, point, t, NULL, ctx)) {
            ERROR_MSG("EC_POINT_get_affine_coordinates_GFp ERROR\n");
            goto error;
        }
    } else { /* NID_X9_62_characteristic_two_field */
# ifndef OPENSSL_NO_EC2M
        if (!EC_POINT_get_affine_coordinates_GF2m(group, point, t, NULL, ctx)) {
            ERROR_MSG("EC_POINT_get_affine_coordinates_GF2m ERROR\n");
            goto error;
        }
# else
        ERROR_MSG("OPENSSL_NO_EC2M ERROR\n");
        goto error;
# endif
    }
    if (!BN_nnmod(t, t, order, ctx)) {
        ERROR_MSG("BN_nnmod ERROR\n");
        goto error;
    }

#ifdef SHOW_DEBUG_ECS
    PrintBN(t);
#endif

    /* check (sG + tP).x + e == sig.r */
    if (!BN_mod_add(t, t, e, order, ctx)) {
        ERROR_MSG("BBN_mod_add ERROR\n");
        goto error;
    }

#ifdef SHOW_DEBUG_ECS
    PrintBN(t);
#endif

    ret = (BN_ucmp(t, sig->r) == 0);
error:
    if (point) EC_POINT_free(point);
    if (order) BN_free(order);
    if (e) BN_free(e);
    if (t) BN_free(t);
    if (ctx) BN_CTX_free(ctx);
    return ret;
}

# if OPENSSL_VERSION_NUMBER < 0x10002000L
/* ecs_locl.h */
struct ecdsa_method {
    const char *name;
    ECDSA_SIG *(*ecdsa_do_sign) (const unsigned char *dgst, int dgst_len,
            const BIGNUM *inv, const BIGNUM *rp,
            EC_KEY *eckey);
    int (*ecdsa_sign_setup) (EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinv,
            BIGNUM **r);
    int (*ecdsa_do_verify) (const unsigned char *dgst, int dgst_len,
            const ECDSA_SIG *sig, EC_KEY *eckey);
# if 0
    int (*init) (EC_KEY *eckey);
    int (*finish) (EC_KEY *eckey);
# endif
    int flags;
    void *app_data;
};

static ECDSA_METHOD sm2_ecdsa_meth = {
    "SM2 ECDSA method",
    sm2dsa_do_sign,
    sm2dsa_sign_setup,
    sm2dsa_do_verify,
    0,                  /* flags */
    NULL                /* app_data */
};

const ECDSA_METHOD *ECDSA_sm2(void)
{
    return &sm2_ecdsa_meth;
}

# else

ECDSA_METHOD *ECDSA_sm2(void)
{
    ECDSA_METHOD *meth = NULL;

    meth = ECDSA_METHOD_new(NULL);
    if (!meth) {
        return NULL;
    }

    ECDSA_METHOD_set_sign(meth, sm2dsa_do_sign);
    ECDSA_METHOD_set_sign_setup(meth, sm2dsa_sign_setup);
    ECDSA_METHOD_set_verify(meth, sm2dsa_do_verify);

    return meth;
}

# endif

/* ==================== test begin ========================= */

/* the input data and results are comming from 
 * GM/T 0003.2-2012 A1 && A.2
 * */
char *ID = "ALICE123@YAHOO.COM";

static char *fp_p  =
"8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3";
static char *fp_a  =
"787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498";
static char *fp_b  =
"63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A";
static char *fp_gx =
"421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D";
static char *fp_gy =
"0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2";
static char *fp_o  =
"8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7";
static char *fp_cf ="1";

static char *fp_pri  =
"128b2fa8bd433c6c068c8d803dff79792a519a55171b1b650c23661d15897263";
static char *fp_pubx =
"0ae4c7798aa0f119471bee11825be46202bb79e2a5844495e97c04ff4df2548a";
static char *fp_puby =
"7c0240f88f1cd4e16352a73c17b7f16f07353e53a176d684a9fe0c6bb798e857";
static char *fp_rnd = 
"6cb28d99385c175c94f94e934817663fc176d925dd72b727260dbaae1fb2f96f";

static char *fp_m = "message digest";

static unsigned char fp_r[] = {
    0x40, 0xf1, 0xec, 0x59, 0xf7, 0x93, 0xd9, 0xf4,
    0x9e, 0x09, 0xdc, 0xef, 0x49, 0x13, 0x0d, 0x41,
    0x94, 0xf7, 0x9f, 0xb1, 0xee, 0xd2, 0xca, 0xa5,
    0x5b, 0xac, 0xdb, 0x49, 0xc4, 0xe7, 0x55, 0xd1
};

static unsigned char fp_s[] = {
    0x6f, 0xc6, 0xda, 0xc3, 0x2c, 0x5d, 0x5c, 0xf1,
    0x0c, 0x77, 0xdf, 0xb2, 0x0f, 0x7c, 0x2e, 0xb6,
    0x67, 0xa4, 0x57, 0x87, 0x2f, 0xb0, 0x9e, 0xc5,
    0x63, 0x27, 0xa6, 0x7e, 0xc7, 0xde, 0xeb, 0xe7
};

static int sm2_ecdsa_test_fp(const int idx)
{
    EC_GROUP *group = NULL;
    EC_KEY *eckey = NULL;
# if OPENSSL_VERSION_NUMBER < 0x10002000L
    const ECDSA_METHOD *meth = NULL;
# else
    ECDSA_METHOD *meth = NULL;
# endif
    ECDSA_SIG *sig = NULL;
    BIGNUM *in_k = NULL;
    unsigned char bin[512];
    int blen;

    group = sm2_create_group(EC_GFp_simple_method(),
            fp_p, fp_a, fp_b, fp_gx, fp_gy, fp_o, fp_cf);
    if (!group) {
        ERROR_MSG("create_sm2_group ERROR\n");
        goto error;
    }

#ifdef SHOW_DEBUG_ECS
    DEBUG_MSG("User eckey\n");
#endif
    eckey = sm2_create_eckey(group, fp_pri, fp_pubx, fp_puby);
    if (!eckey) {
        ERROR_MSG("sm2_create_eckey ERROR\n");
        goto error;
    }

    meth = ECDSA_sm2();
    if (!meth) {
        ERROR_MSG("ECDSA_sm2 ERROR\n");
        goto error;
    }

    /* set method */
    if (!ECDSA_set_method(eckey, meth)) {
        ERROR_MSG("ECDSA_set_method ERROR\n");
        goto error;
    }

    /* set ID */
    setDefID(ID);

    /* set random */
    if (!(in_k = BN_new()) || !BN_hex2bn(&in_k, fp_rnd)) {
        ERROR_MSG("BN_hex2bn ERROR\n");
        goto error;
    }

    sig = ECDSA_do_sign_ex((unsigned char *)fp_m, strlen(fp_m), in_k, NULL, eckey);
    if (!sig) {
        ERROR_MSG("ECDSA_do_sign ERROR\n");
        goto error;
    }

    blen = BN_bn2bin(sig->r, bin);
    if (blen != sizeof (fp_r) || memcmp(bin, fp_r, blen)) {
        ERROR_MSG("%s ----------> testcase[%d] ERROR\n", __FUNCTION__, idx);
        goto error;
    }
    blen = BN_bn2bin(sig->s, bin);
    if (blen != sizeof (fp_s) || memcmp(bin, fp_s, blen)) {
        ERROR_MSG("%s ----------> testcase[%d] ERROR\n", __FUNCTION__, idx);
        goto error;
    }

    if (ECDSA_do_verify((unsigned char *)fp_m, strlen(fp_m), sig, eckey) <= 0) {
        ERROR_MSG("ECDSA_do_verify ERROR\n");
        goto error;
    }

    printf("%s ----------> testcase[%d] ok\n", __FUNCTION__, idx);
error:
    if (group) EC_GROUP_free(group);
    if (eckey) EC_KEY_free(eckey);
    if (sig) ECDSA_SIG_free(sig);
# if OPENSSL_VERSION_NUMBER >= 0x10002000L
    if (meth) ECDSA_METHOD_free(meth);
# endif
    if (in_k) BN_free(in_k);

    return 0;
}

# ifndef OPENSSL_NO_EC2M
/* the input data and results are comming from 
 * GM/T 0003.2-2012 A3
 * */
static char *f2m_p =  
"020000000000000000000000000000000000000000000000000000000000001001";
static char *f2m_a = "0";
static char *f2m_b =  
"00e78bcd09746c202378a7e72b12bce00266b9627ecb0b5a25367ad1ad4cc6242b";
static char *f2m_gx = 
"00cdb9ca7f1e6b0441f658343f4b10297c0ef9b6491082400a62e7a7485735fadd";
static char *f2m_gy = 
"013de74da65951c4d76dc89220d5f7777a611b1c38bae260b175951dc8060c2b3e";
static char *f2m_o =  
"7fffffffffffffffffffffffffffffffbc972cf7e6b6f900945b3c6a0cf6161d";
static char *f2m_cf = "4";

static char *f2m_pri =
"771ef3dbff5f1cdc32b9c572930476191998b2bf7cb981d7f5b39202645f0931";
static char *f2m_pubx=
"0165961645281a8626607b917f657d7e9382f1ea5cd931f40f6627f357542653b2";
static char *f2m_puby=
"01686522130d590fb8de635d8fca715cc6bf3d05bef3f75da5d543454448166612";
static char *f2m_rnd =
"36cd79fc8e24b7357a8a7b4a46d454c397703d6498158c605399b341ada186d6";

static char *f2m_m = "message digest";

static unsigned char f2m_r[] = {
    0x6d, 0x3f, 0xba, 0x26, 0xea, 0xb2, 0xa1, 0x05,
    0x4f, 0x5d, 0x19, 0x83, 0x32, 0xe3, 0x35, 0x81,
    0x7c, 0x8a, 0xc4, 0x53, 0xed, 0x26, 0xd3, 0x39,
    0x1c, 0xd4, 0x43, 0x9d, 0x82, 0x5b, 0xf2, 0x5b
};

static unsigned char f2m_s[] = {
    0x31, 0x24, 0xc5, 0x68, 0x8d, 0x95, 0xf0, 0xa1,
    0x02, 0x52, 0xa9, 0xbe, 0xd0, 0x33, 0xbe, 0xc8,
    0x44, 0x39, 0xda, 0x38, 0x46, 0x21, 0xb6, 0xd6,
    0xfa, 0xd7, 0x7f, 0x94, 0xb7, 0x4a, 0x95, 0x56
};

static int sm2_ecdsa_test_f2m(const int idx)
{
    EC_GROUP *group = NULL;
    EC_KEY *eckey = NULL;
# if OPENSSL_VERSION_NUMBER < 0x10002000L
    const ECDSA_METHOD *meth = NULL;
# else
    ECDSA_METHOD *meth = NULL;
# endif
    ECDSA_SIG *sig = NULL;
    BIGNUM *in_k = NULL;
    unsigned char bin[512];
    int blen;

    group = sm2_create_group(EC_GF2m_simple_method(),
            f2m_p, f2m_a, f2m_b, f2m_gx, f2m_gy, f2m_o, f2m_cf);
    if (!group) {
        ERROR_MSG("create_sm2_group ERROR\n");
        goto error;
    }

#ifdef SHOW_DEBUG_ECS
    DEBUG_MSG("User eckey\n");
#endif
    eckey = sm2_create_eckey(group, f2m_pri, f2m_pubx, f2m_puby);
    if (!eckey) {
        ERROR_MSG("sm2_create_eckey ERROR\n");
        goto error;
    }

    meth = ECDSA_sm2();
    if (!meth) {
        ERROR_MSG("ECDSA_sm2 ERROR\n");
        goto error;
    }

    /* set method */
    if (!ECDSA_set_method(eckey, meth)) {
        ERROR_MSG("ECDSA_set_method ERROR\n");
        goto error;
    }

    /* set ID */
    setDefID(ID);

    /* set random */
    if (!(in_k = BN_new()) || !BN_hex2bn(&in_k, f2m_rnd)) {
        ERROR_MSG("BN_hex2bn ERROR\n");
        goto error;
    }

    sig = ECDSA_do_sign_ex((unsigned char *)f2m_m, strlen(f2m_m), 
            in_k, NULL, eckey);
    if (!sig) {
        ERROR_MSG("ECDSA_do_sign ERROR\n");
        goto error;
    }

    blen = BN_bn2bin(sig->r, bin);
    if (blen != sizeof (f2m_r) || memcmp(bin, f2m_r, blen)) {
        ERROR_MSG("%s ----------> testcase[%d] ERROR\n", __FUNCTION__, idx);
        goto error;
    }
    blen = BN_bn2bin(sig->s, bin);
    if (blen != sizeof (f2m_s) || memcmp(bin, f2m_s, blen)) {
        ERROR_MSG("%s ----------> testcase[%d] ERROR\n", __FUNCTION__, idx);
        goto error;
    }

    if (ECDSA_do_verify((unsigned char *)f2m_m, strlen(f2m_m), sig, eckey) <= 0) {
        ERROR_MSG("ECDSA_do_verify ERROR\n");
        goto error;
    }

    printf("%s ----------> testcase[%d] ok\n", __FUNCTION__, idx);
error:
    if (group) EC_GROUP_free(group);
    if (eckey) EC_KEY_free(eckey);
    if (sig) ECDSA_SIG_free(sig);
# if OPENSSL_VERSION_NUMBER >= 0x10002000L
    if (meth) ECDSA_METHOD_free(meth);
# endif
    if (in_k) BN_free(in_k);

    return 0;
    return 0;
}
# endif

int sm2_ecdsa_test(int argc, char *argv[])
{
    sm2_ecdsa_test_fp(1);
# ifndef OPENSSL_NO_EC2M
    sm2_ecdsa_test_f2m(2);
# endif

    return 0;
}
