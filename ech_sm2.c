/* Copyright (C) lnwdl (lnwdl@163.com)
 * All rights reserved.
 *
 * SM2 ecdh.
 */

#include <string.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include "public.h"
#include "evp_sm3.h"
#include "ech_sm2.h"

int sm2_compute_key(void *out, size_t outlen, 
        EC_KEY *eckey, const BIGNUM *rnd, const char *id,   /* local */
        const EC_POINT *r_pubrnd,                       /* remote*/ 
        const EC_POINT *r_pubkey, 
        const char *r_id,
        int is_initiator) /* is initiator or not */
{
    BN_CTX *ctx = NULL;
    const EC_GROUP *group;
    const BIGNUM *l_prikey;
    BIGNUM *order, *l_pubrnd_x, *l_pubrnd_x_plus, *t, 
           *r_pubrnd_x, *r_pubrnd_x_plus, *w_big, *w_exp, *h, *xv, *yv;
    BIGNUM *l_rnd = NULL;
    EC_POINT *l_pubrnd = NULL, *V = NULL;
    const EC_POINT *l_pubkey = NULL; 
    const EVP_MD *md = EVP_sm3();
    int ret = 0, w_mask, is_prime, degree;
    size_t i, blen, Zalen, Zblen;
    unsigned char *buf = NULL, *p;
    unsigned char Za[EVP_MAX_MD_SIZE], Zb[EVP_MAX_MD_SIZE];

    ctx = BN_CTX_new();
    if (!ctx) {
        goto error;
    }
    BN_CTX_start(ctx);

    order = BN_CTX_get(ctx);
    l_pubrnd_x = BN_CTX_get(ctx);
    l_pubrnd_x_plus = BN_CTX_get(ctx);
    t = BN_CTX_get(ctx);
    r_pubrnd_x = BN_CTX_get(ctx);
    r_pubrnd_x_plus = BN_CTX_get(ctx);
    w_big = BN_CTX_get(ctx);
    w_exp = BN_CTX_get(ctx);
    h = BN_CTX_get(ctx);
    xv = BN_CTX_get(ctx);
    yv = BN_CTX_get(ctx);

    group = EC_KEY_get0_group(eckey);
    if (!group) {
        goto error;
    }

    if (!EC_GROUP_get_order(group, order, ctx)) {
        goto error;
    }
    degree = EC_GROUP_get_degree(group);

    l_prikey = EC_KEY_get0_private_key(eckey);
    if (!l_prikey) {
        goto error;
    }

    l_pubkey = EC_KEY_get0_public_key(eckey);
    if (!l_pubkey) {
        goto error;
    }

    is_prime = (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) 
            == NID_X9_62_prime_field);

#ifdef SHOW_DEBUG_ECH
    PrintBN(l_prikey);
#endif

    if (!rnd) { /* if the local random is null, generate it */
        l_rnd = BN_new();
        if (!l_rnd) {
            goto error;
        }

        do {
            if (!BN_rand_range(l_rnd, order)) {
                goto error;
            }
        } while (BN_is_zero(l_rnd));
    } else {
        l_rnd = BN_dup(rnd);
    }

#ifdef SHOW_DEBUG_ECH
    PrintBN(l_rnd);
#endif

    l_pubrnd = EC_POINT_new(group);
    if (!l_pubrnd) {
        goto error;
    }

    if (!EC_POINT_mul(group, l_pubrnd, l_rnd, NULL, NULL, ctx)) {
        goto error;
    }

    if (is_prime) {
        if (!EC_POINT_get_affine_coordinates_GFp(group, l_pubrnd, 
                    l_pubrnd_x, NULL, ctx)) {
            goto error;
        }
    } else {
# ifndef OPENSSL_NO_EC2M
        if (!EC_POINT_get_affine_coordinates_GF2m(group, l_pubrnd, 
                    l_pubrnd_x, NULL, ctx)) {
            goto error;
        }
# else
        ERROR_MSG("OPENSSL_NO_EC2M ERROR\n");
        goto error;
# endif
    }

#ifdef SHOW_DEBUG_ECH
    PrintBN(l_pubrnd_x);
#endif

    w_mask = (BN_num_bits(order) + 1) / 2 - 1;
#ifdef SHOW_DEBUG_ECH
    DEBUG_MSG("w_mask: %d\n", w_mask);
#endif
    BN_set_word(w_big, w_mask); /* w */
    BN_set_word(w_exp, 2);
    BN_exp(w_exp, w_exp, w_big, ctx); /* 2^w */

    BN_mask_bits(l_pubrnd_x, w_mask); /* x & (2^w - 1) */
    BN_add(l_pubrnd_x_plus, w_exp, l_pubrnd_x);
#ifdef SHOW_DEBUG_ECH
    PrintBN(l_pubrnd_x_plus);
#endif

    /* t = prikey + pubrndx_plus * rnd */
    BN_mod_mul(t, l_pubrnd_x_plus, l_rnd, order, ctx);
    BN_mod_add_quick(t, t, l_prikey, order);
#ifdef SHOW_DEBUG_ECH
    PrintBN(t);
#endif

    if (is_prime) {
        if (!EC_POINT_get_affine_coordinates_GFp(group, r_pubrnd, 
                    r_pubrnd_x, NULL, ctx)) {
            goto error;
        }
    } else {
# ifndef OPENSSL_NO_EC2M
        if (!EC_POINT_get_affine_coordinates_GF2m(group, r_pubrnd, 
                    r_pubrnd_x, NULL, ctx)) {
            goto error;
        }
# else
        ERROR_MSG("OPENSSL_NO_EC2M ERROR\n");
        goto error;
# endif
    }

#ifdef SHOW_DEBUG_ECH
    PrintBN(r_pubrnd_x);
#endif

    BN_mask_bits(r_pubrnd_x, w_mask); /* x & (2^w - 1) */
    BN_add(r_pubrnd_x_plus, w_exp, r_pubrnd_x);
#ifdef SHOW_DEBUG_ECH
    PrintBN(r_pubrnd_x_plus);
#endif

    /* r_pubkey + r_pubrnd_x_plus * r_pubrnd */
    V = EC_POINT_new(group);
    if (!V) {
        goto error;
    }
    if (!EC_POINT_mul(group, V, NULL, r_pubrnd, r_pubrnd_x_plus, ctx)) {
        goto error;
    }
    if (!EC_POINT_add(group, V, r_pubkey, V, ctx)) {
        goto error;
    }

    if (!EC_GROUP_get_cofactor(group, h, ctx)) {
        goto error;
    }
    BN_mod_mul(t, t, h, order, ctx);
#ifdef SHOW_DEBUG_ECH
    PrintBN(t);
#endif

    if (!EC_POINT_mul(group, V, NULL, V, t, ctx)) {
        goto error;
    }

    if (is_prime) {
        if (!EC_POINT_get_affine_coordinates_GFp(group, V, 
                    xv, yv, ctx)) {
            goto error;
        }
    } else {
# ifndef OPENSSL_NO_EC2M
        if (!EC_POINT_get_affine_coordinates_GF2m(group, V, 
                    xv, yv, ctx)) {
            goto error;
        }
# else
        ERROR_MSG("OPENSSL_NO_EC2M ERROR\n");
        goto error;
# endif
    }

#ifdef SHOW_DEBUG_ECH
    DEBUG_MSG("coordinates of Key Point V are: \n");
    PrintBN(xv);
    PrintBN(yv);
#endif

    /* compute the user ext info of initiator */
    Zalen = sizeof (Za) / sizeof (unsigned char);
    Zblen = sizeof (Zb) / sizeof (unsigned char);
    if (is_initiator) {
        if (!getUserExtInfo(eckey, l_pubkey, md, 
                    (unsigned char *)id, strlen(id), Za, &Zalen)) {
            goto error;
        }

        if (!getUserExtInfo(eckey, r_pubkey, md, 
                    (unsigned char *)r_id, strlen(r_id), Zb, &Zblen)) {
            goto error;
        }
    } else {
        if (!getUserExtInfo(eckey, r_pubkey, md, 
                    (unsigned char *)r_id, strlen(r_id), Za, &Zalen)) {
            goto error;
        }

        if (!getUserExtInfo(eckey, l_pubkey, md, 
                    (unsigned char *)id, strlen(id), Zb, &Zblen)) {
            goto error;
        }
    }

#ifdef SHOW_DEBUG_ECH
    DEBUG_MSG("Za is: \n");
    ShwHexBuf(Za, Zalen);
    DEBUG_MSG("Zb is: \n");
    ShwHexBuf(Zb, Zblen);
#endif

    blen = BN_num_bytes(xv) + BN_num_bytes(yv) + Zalen + Zblen;
    buf = OPENSSL_malloc(blen * sizeof (unsigned char));
    if (!buf) {
        goto error;
    }

    p = buf;
    i = BN_bn2bin_gm(xv, p, degree);
    p += i;
    i = BN_bn2bin_gm(yv, p, degree);
    p += i;
    memcpy(p, Za, Zalen);
    p += Zalen;
    memcpy(p, Zb, Zblen);
    
#ifdef SHOW_DEBUG_ECH
    DEBUG_MSG("[xv || yv || Za || Zb]:\n");
    ShwHexBuf(buf, blen);
#endif

    if (!myECDH_KDF_X9_62(out, outlen, buf, blen, NULL, 0, md)) {
        goto error;
    }

#ifdef SHOW_DEBUG_ECH
    DEBUG_MSG("myECDH_KDF_X9_62 compute Share Key is:\n");
    ShwHexBuf(out, outlen);
#endif

    ret = 1;
error:
    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if (l_rnd) BN_free(l_rnd);
    if (l_pubrnd) EC_POINT_free(l_pubrnd);
    if (V) EC_POINT_free(V);
    if (buf) OPENSSL_free(buf);

    return ret;
}

/* ==================== test begin ========================= */

/* the input data are comming from 
 * GM/T 0003.3-2012 A.1
 * */
static char *IDA = "ALICE123@YAHOO.COM";
static char *IDB = "BILL456@YAHOO.COM";

/* the input data and results are comming from 
 * GM/T 0003.3-2012 A.2
 * */
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

static char *fp_Apri  =
"6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE";
static char *fp_Apubx =
"3099093BF3C137D8FCBBCDF4A2AE50F3B0F216C3122D79425FE03A45DBFE1655";
static char *fp_Apuby =
"3DF79E8DAC1CF0ECBAA2F2B49D51A4B387F2EFAF482339086A27A8E05BAED98B";
static char *fp_Arnd  =
"83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563";
static char *fp_Bpri  =
"5e35d7d3f3c54dbac72e61819e730b019a84208ca3a35e4c2e353dfccb2a3b53";
static char *fp_Bpubx =
"245493d446c38d8cc0f118374690e7df633a8a4bfb3329b5ece604b2b4f37f43";
static char *fp_Bpuby =
"53c0869f4b9e17773de68fec45e14904e0dea45bf6cecf9918c85ea047c60a4c";
static char *fp_Brnd  =
"33fe21940342161c55619c4a0c060293d543c80af19748ce176d83477de71c80";

static unsigned char fp_ret[] = {
    0x55, 0xb0, 0xac, 0x62, 
    0xa6, 0xb9, 0x27, 0xba, 
    0x23, 0x70, 0x38, 0x32, 
    0xc8, 0x53, 0xde, 0xd4
};

static int sm2_ecdh_test_GFp(const int idx)
{
	EC_GROUP *group = NULL;
	EC_KEY *eckeyA = NULL, *eckeyB = NULL;
    BIGNUM *x = NULL, *y = NULL;
    BIGNUM *rA = NULL, *rB = NULL;
    const EC_POINT *pubA = NULL, *pubB = NULL;
    EC_POINT *Ra = NULL, *Rb = NULL;
    unsigned char *SA = NULL, *SB = NULL;
	size_t Zlen;
	
    /* group */
    group = sm2_create_group(EC_GFp_simple_method(), 
            fp_p, fp_a, fp_b, fp_gx, fp_gy, fp_o, fp_cf);
    if (!group) {
        ERROR_MSG("create_sm2_group ERROR\n");
        goto error;
    }

    /* user eckey */
#ifdef SHOW_DEBUG_ECH
    DEBUG_MSG("User A eckey\n");
#endif
    eckeyA = sm2_create_eckey(group, fp_Apri, fp_Apubx, fp_Apuby);
#ifdef SHOW_DEBUG_ECH
    DEBUG_MSG("User B eckey\n");
#endif
    eckeyB = sm2_create_eckey(group, fp_Bpri, fp_Bpubx, fp_Bpuby);

    pubA = EC_KEY_get0_public_key(eckeyA);
    pubB = EC_KEY_get0_public_key(eckeyB);

    /* random and R of User A and B */
    rA = BN_new();
    Ra = EC_POINT_new(group);
    BN_hex2bn(&rA, fp_Arnd);
	if (!EC_POINT_mul(group, Ra, rA, NULL, NULL, NULL)) {
        ERROR_MSG("EC_POINT_mul ERROR\n");
        goto error;
    }

    x = BN_new();
    y = BN_new();
    if (!x || !y) {
        ERROR_MSG("BN_new ERROR\n");
        goto error;
    }

	if (!EC_POINT_get_affine_coordinates_GFp(group, Ra, x, y, NULL)) {
        ERROR_MSG("EC_POINT_get_affine_coordinates_GFp ERROR\n");
        goto error;
    }

#ifdef SHOW_DEBUG_ECH
    PrintBN(rA);
	DEBUG_MSG("User A random Point Ra:\n");
    PrintBN(x);
    PrintBN(y);
#endif

    rB = BN_new();
    Rb = EC_POINT_new(group);
    BN_hex2bn(&rB, fp_Brnd);
	if (!EC_POINT_mul(group, Rb, rB, NULL, NULL, NULL)) {
        ERROR_MSG("EC_POINT_mul ERROR\n");
        goto error;
    }

	if (!EC_POINT_get_affine_coordinates_GFp(group, Rb, x, y, NULL)) {
        ERROR_MSG("EC_POINT_get_affine_coordinates_GFp ERROR\n");
        goto error;
    }

#ifdef SHOW_DEBUG_ECH
    PrintBN(rB);
	DEBUG_MSG("User B random Point Rb:\n");
    PrintBN(x);
    PrintBN(y);
#endif

    /* user extension info */
    Zlen = 128 / 8;
    SB = OPENSSL_malloc(Zlen);
    if (!SB) {
        ERROR_MSG("OPENSSL_malloc ERROR\n");
        goto error;
    }

#ifdef SHOW_DEBUG_ECH
	DEBUG_MSG("User B compute Share Key begin:\n");
#endif
    /* User B compute share key */
    sm2_compute_key(SB, Zlen,
            eckeyB, rB, IDB,
            Ra, pubA, IDA, 0);

#ifdef SHOW_DEBUG_ECH
	DEBUG_MSG("User B compute Share Key is:\n");
    ShwHexBuf(SB, Zlen);
#endif

    SA = OPENSSL_malloc(Zlen);
    if (!SA) {
        ERROR_MSG("OPENSSL_malloc ERROR\n");
        goto error;
    }

#ifdef SHOW_DEBUG_ECH
	DEBUG_MSG("User A compute Share Key begin:\n");
#endif
    /* User A compute share key */
    sm2_compute_key(SA, Zlen,
            eckeyA, rA, IDA,
            Rb, pubB, IDB, 1);

#ifdef SHOW_DEBUG_ECH
	DEBUG_MSG("User A compute Share Key is:\n");
    ShwHexBuf(SA, Zlen);
#endif

    if (memcmp(SA, SB, Zlen) == 0
            && memcmp(SA, fp_ret, Zlen) == 0) {
        printf("%s ----------> testcase[%d] ok\n", __FUNCTION__, idx);
    } else {
        ERROR_MSG("%s ----------> testcase[%d] ERROR\n", __FUNCTION__, idx);
    }

error:
    BN_free(x);
    BN_free(y);
    EC_GROUP_free(group);
	EC_KEY_free(eckeyA);
	EC_KEY_free(eckeyB);
    BN_free(rA);
    BN_free(rB);
    EC_POINT_free(Ra);
    EC_POINT_free(Rb);
    if (SA) OPENSSL_free(SA);
    if (SB) OPENSSL_free(SB);

	return 0;
}

# ifndef OPENSSL_NO_EC2M
/* the input data are comming from 
 * GM/T 0003.3-2012 A.3
 * but the results(started in Za) are incorrect in the specification,
 * so I don't list them here.
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

static char *f2m_Apri =
"4813903d254f2c20a94bc5704238496954bb5279f861952ef2c5298e84d2ceaa";
static char *f2m_Apubx=
"008e3bdb2e11f9193388f1f901ccc857bf49cfc065fb38b9069caae6d5afc3592f";
static char *f2m_Apuby=
"004555122aac0075f42e0a8bbd2c0665c789120df19d77b4e3ee4712f598040415";
static char *f2m_Arnd =
"54a3d6673ff3a6bd6b02ebb164c2a3af6d4a4906229d9bfce68cc366a2e64ba4";
static char *f2m_Bpri =
"08f41bae0922f47c212803fe681ad52b9bf28a35e1cd0ec273a2cf813e8fd1dc";
static char *f2m_Bpubx=
"0034297dd83ab14d5b393b6712f32b2f2e938d4690b095424b89da880c52d4a7d9";
static char *f2m_Bpuby=
"0199bbf11ac95a0ea34bbd00ca50b93ec24acb68335d20ba5dcfe3b33bdbd2b62d";
static char *f2m_Brnd =
"1f21933387bef781d0a8f7fd708c5ae0a56ee3f423dbc2fe5bdf6f068c53f7ad";

static int sm2_ecdh_test_GF2m(const int idx)
{
	EC_GROUP *group = NULL;
	EC_KEY *eckeyA = NULL, *eckeyB = NULL;
    BIGNUM *x = NULL, *y = NULL;
    BIGNUM *rA = NULL, *rB = NULL;
    const EC_POINT *pubA = NULL, *pubB = NULL;
    EC_POINT *Ra = NULL, *Rb = NULL;
    unsigned char *SA = NULL, *SB = NULL;
	size_t Zlen;
	
    /* group */
    group = sm2_create_group(EC_GF2m_simple_method(), 
            f2m_p, f2m_a, f2m_b, f2m_gx, f2m_gy, f2m_o, f2m_cf);
    if (!group) {
        ERROR_MSG("create_sm2_group ERROR\n");
        goto error;
    }

    /* user eckey */
#ifdef SHOW_DEBUG_ECH
    DEBUG_MSG("User A eckey\n");
#endif
    eckeyA = sm2_create_eckey(group, f2m_Apri, f2m_Apubx, f2m_Apuby);
#ifdef SHOW_DEBUG_ECH
    DEBUG_MSG("User B eckey\n");
#endif
    eckeyB = sm2_create_eckey(group, f2m_Bpri, f2m_Bpubx, f2m_Bpuby);

    pubA = EC_KEY_get0_public_key(eckeyA);
    pubB = EC_KEY_get0_public_key(eckeyB);

    /* random and R of User A and B */
    rA = BN_new();
    Ra = EC_POINT_new(group);
    BN_hex2bn(&rA, f2m_Arnd);
	if (!EC_POINT_mul(group, Ra, rA, NULL, NULL, NULL)) {
        ERROR_MSG("EC_POINT_mul ERROR\n");
        goto error;
    }

    x = BN_new();
    y = BN_new();
    if (!x || !y) {
        ERROR_MSG("BN_new ERROR\n");
        goto error;
    }

	if (!EC_POINT_get_affine_coordinates_GFp(group, Ra, x, y, NULL)) {
        ERROR_MSG("EC_POINT_get_affine_coordinates_GFp ERROR\n");
        goto error;
    }

#ifdef SHOW_DEBUG_ECH
    PrintBN(rA);
	DEBUG_MSG("User A random Point Ra:\n");
    PrintBN(x);
    PrintBN(y);
#endif

    rB = BN_new();
    Rb = EC_POINT_new(group);
    BN_hex2bn(&rB, f2m_Brnd);
	if (!EC_POINT_mul(group, Rb, rB, NULL, NULL, NULL)) {
        ERROR_MSG("EC_POINT_mul ERROR\n");
        goto error;
    }

	if (!EC_POINT_get_affine_coordinates_GFp(group, Rb, x, y, NULL)) {
        ERROR_MSG("EC_POINT_get_affine_coordinates_GFp ERROR\n");
        goto error;
    }

#ifdef SHOW_DEBUG_ECH
    PrintBN(rB);
	DEBUG_MSG("User B random Point Rb:\n");
    PrintBN(x);
    PrintBN(y);
#endif

    /* user extension info */
    Zlen = 128 / 8;
    SB = OPENSSL_malloc(Zlen);
    if (!SB) {
        ERROR_MSG("OPENSSL_malloc ERROR\n");
        goto error;
    }

#ifdef SHOW_DEBUG_ECH
	DEBUG_MSG("User B compute Share Key begin:\n");
#endif
    /* User B compute share key */
    sm2_compute_key(SB, Zlen,
            eckeyB, rB, IDB,
            Ra, pubA, IDA, 0);

#ifdef SHOW_DEBUG_ECH
	DEBUG_MSG("User B compute Share Key is:\n");
    ShwHexBuf(SB, Zlen);
#endif

    SA = OPENSSL_malloc(Zlen);
    if (!SA) {
        ERROR_MSG("OPENSSL_malloc ERROR\n");
        goto error;
    }

#ifdef SHOW_DEBUG_ECH
	DEBUG_MSG("User A compute Share Key begin:\n");
#endif
    /* User A compute share key */
    sm2_compute_key(SA, Zlen,
            eckeyA, rA, IDA,
            Rb, pubB, IDB, 1);

#ifdef SHOW_DEBUG_ECH
	DEBUG_MSG("User A compute Share Key is:\n");
    ShwHexBuf(SA, Zlen);
#endif

    if (memcmp(SA, SB, Zlen) == 0) {
        printf("%s ----------> testcase[%d] ok\n", __FUNCTION__, idx);
    } else {
        ERROR_MSG("%s ----------> testcase[%d] ERROR\n", __FUNCTION__, idx);
    }

error:
    BN_free(x);
    BN_free(y);
    EC_GROUP_free(group);
	EC_KEY_free(eckeyA);
	EC_KEY_free(eckeyB);
    BN_free(rA);
    BN_free(rB);
    EC_POINT_free(Ra);
    EC_POINT_free(Rb);
    if (SA) OPENSSL_free(SA);
    if (SB) OPENSSL_free(SB);

	return 0;
}
# endif

int sm2_ecdh_test(int argc, char *argv[])
{
    sm2_ecdh_test_GFp(1);
# ifndef OPENSSL_NO_EC2M
    sm2_ecdh_test_GF2m(2);
# endif

    return 0;
}
