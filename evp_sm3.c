/* Copyright (C) lnwdl (lnwdl@163.com)
 * All rights reserved.
 *
 * SM3 digest EVP.
 */

#include <string.h>
#include <stdlib.h>
#include "public.h"
#include "evp_sm3.h"

#define SM3_CBLOCK          64
#define SM3_DIGEST_LENGTH   32

#define nid_sm3             0   /* TODO */
#define nid_sm2_with_sm3    0   /* TODO */

typedef struct SM3state_st {
    unsigned long digest[8];
    unsigned char block[SM3_CBLOCK];
    size_t nblock;  /* block counter */
    size_t offset;  /* empty offset in @block */
} SM3_CTX;

static int SM3_Init(SM3_CTX *ctx)
{
    /* IV */
    ctx->digest[0] = 0x7380166F;
    ctx->digest[1] = 0x4914B2B9;
    ctx->digest[2] = 0x172442D7;
    ctx->digest[3] = 0xDA8A0600;
    ctx->digest[4] = 0xA96F30BC;
    ctx->digest[5] = 0x163138AA;
    ctx->digest[6] = 0xE38DEE4D;
    ctx->digest[7] = 0xB0FB0E4E;

    /* leave the block unset */

    ctx->nblock = 0;
    ctx->offset = 0;

    return 1;
}

#define GET_LONG(a) (   \
        ((a)[0] << 24)       \
        | ((a)[1] << 16)     \
        | ((a)[2] << 8)      \
        | (a)[3])

#define ROLL_LEFT(l, n) (((l) << (n)) | ((l) >> (32 - (n))))

#define P1(l) ((l) ^ ROLL_LEFT((l), 15) ^ ROLL_LEFT((l), 23))

static void sm3_extend(const unsigned char block[64], 
        unsigned long W[68], unsigned long W_plus[64])
{
#ifdef SHOW_DEBUG_SM3
    DEBUG_MSG("input block is:\n");
    ShwHexBuf(block, 64);
#endif

    size_t j;

    /* a) */
    for (j = 0; j < 16; ++j) {
        W[j] = GET_LONG(block + j * 4);
    }

    /* b) */
    for (j = 16; j < 68; ++j) {
        W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROLL_LEFT(W[j - 3], 15))
                ^ ROLL_LEFT(W[j - 13], 7)
                ^ W[j - 6];
    }

    /* c) */
    for (j = 0; j < 64; ++j) {
        W_plus[j] = W[j] ^ W[j + 4];
    }

#ifdef SHOW_DEBUG_SM3
    printf("W:\n");
    for (j = 0; j < 68; ++j) {
        printf("%08x ", (unsigned)W[j]);
        if (!((j + 1) % 8)) {
            printf("\n");
        }
    }
    printf("\n");

    printf("W_plus:\n");
    for (j = 0; j < 64; ++j) {
        printf("%08x ", (unsigned)W_plus[j]);
        if (!((j + 1) % 8)) {
            printf("\n");
        }
    }
    printf("\n");
#endif
}

#define T(j) ((j <= 15) ? 0x79cc4519 : 0x7a879d8a)

#define FF(j, X, Y, Z) \
    (((j) <= 15) ? ((X) ^ (Y) ^ (Z)) : \
        (((X) & (Y)) | ((X) & (Z)) | ((Y) & (Z))))

#define GG(j, X, Y, Z) \
    (((j) <= 15) ? ((X) ^ (Y) ^ (Z)) : \
        (((X) & (Y)) | ((~(X)) & (Z))))

#define P0(l) ((l) ^ ROLL_LEFT((l), 9) ^ ROLL_LEFT((l), 17))

static void sm3_compress(unsigned long digest[8], const unsigned char block[64])
{
    size_t j;
    unsigned long W[68], W_plus[64];
    unsigned long SS1, SS2, TT1, TT2;
    unsigned long A = digest[0];
    unsigned long B = digest[1];
    unsigned long C = digest[2];
    unsigned long D = digest[3];
    unsigned long E = digest[4];
    unsigned long F = digest[5];
    unsigned long G = digest[6];
    unsigned long H = digest[7];

    sm3_extend(block, W, W_plus); 

    for (j = 0; j < 64; ++j) {
        SS1 = ROLL_LEFT((ROLL_LEFT(A, 12) + E + ROLL_LEFT(T(j), j % 32)), 7);
        SS2 = SS1 ^ ROLL_LEFT(A, 12);
        TT1 = FF(j, A, B, C) + D + SS2 + W_plus[j];
        TT2 = GG(j, E, F, G) + H + SS1 + W[j];
        D = C;
        C = ROLL_LEFT(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROLL_LEFT(F, 19);
        F = E;
        E = P0(TT2);

#ifdef SHOW_DEBUG_SM3
    printf("[%02d] A-H:%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x\n",
            (unsigned) j,
            (unsigned) A,
            (unsigned) B,
            (unsigned) C,
            (unsigned) D,
            (unsigned) E,
            (unsigned) F,
            (unsigned) G,
            (unsigned) H);
#endif
    }

    digest[0] ^= A;
    digest[1] ^= B;
    digest[2] ^= C;
    digest[3] ^= D;
    digest[4] ^= E;
    digest[5] ^= F;
    digest[6] ^= G;
    digest[7] ^= H;

}

static int SM3_Update(SM3_CTX *ctx, const void *in, size_t len)
{
    size_t left;
    const unsigned char *data = (const unsigned char *)in;

    /* handle the left data last update, append data */
    if (ctx->offset) {
        left = sizeof (ctx->block) - ctx->offset;

        if (len < left) { 
            /* not filled a block, 
             * just return and hande it next time(update/final)
             * */
            memcpy(ctx->block + ctx->offset, data, len);
            ctx->offset += len;
            return 1;
        } else {
            memcpy(ctx->block + ctx->offset, data, left);

            /* the block is full, do compress, 
             * incress the block counter,
             * shrink the input data 
             * */
            sm3_compress(ctx->digest, ctx->block);
            ctx->nblock++;
            data += left;
            len -= left;
        }
    }

    /* handle the left input data */
    while (len >= sizeof (ctx->block)) {
        sm3_compress(ctx->digest, data);
        ctx->nblock++;
        data += sizeof (ctx->block);
        len -= sizeof (ctx->block);
    }

    /* leave the addition data for next time handing(update/final) */
    ctx->offset = len;
    memcpy(ctx->block, data, len);

    return 1;
}

#define PUT_LONG(a, l) \
    do {    \
        ((unsigned char *)(a))[0] = ((l) >> 24) & 0xff;  \
        ((unsigned char *)(a))[1] = ((l) >> 16) & 0xff;  \
        ((unsigned char *)(a))[2] = ((l) >> 8) & 0xff;   \
        ((unsigned char *)(a))[3] = (l) & 0xff;          \
    } while (0)

static void sm3_padding(SM3_CTX *ctx)
{
    ctx->block[ctx->offset] = 0x80;

    if (ctx->offset + 8 < sizeof (ctx->block)) {
        /* the left is long enough for 65bits(1bits(1) + 64bits(len)) 
         * leave the last 8 bytes for value input data length
         * */
        memset(ctx->block + ctx->offset + 1, 0, 
                sizeof (ctx->block) - ctx->offset - 1 - 8);
    } else {
        /* padding 0 till the block end,
         * need another iterator of compress 
         * */
        memset(ctx->block + ctx->offset + 1, 0,
                sizeof (ctx->block) - ctx->offset - 1);
        sm3_compress(ctx->digest, ctx->block);
        /* padding 0 till the last 8 bytes */
        memset(ctx->block, 0, sizeof (ctx->block) - 8);
    }

    /* the last 8 tyes always filled with the input data bit length 
     * total_byte_len = ctx->nblock * 64 + ctx->offset
     *                  = (ctx->nblock << 6) + ctx->offset;
     * total_bit_len = total_byte_len * 8 = total_byte_len << 3
     *                  = (ctx->nblock << 9) + (ctx->offset << 3);
     * array[0] = total_bit_len >> 32 = (ctx->nblock >> 23) + (ctx->offset >> 29);
     *  && the ctx->offset max_byte_len = 64 = 2 << 6
     *                      max_bit_len = max_byte_len << 3 = 2 << 9
     * so ctx->offset >> 29 will always be 0;
     * */
    PUT_LONG(ctx->block + sizeof (ctx->block) - 8, 
            (ctx->nblock >> 23));
    PUT_LONG(ctx->block + sizeof (ctx->block) - 4, 
            ((ctx->nblock << 9) + (ctx->offset << 3)));

}

static int SM3_Final(unsigned char *md, SM3_CTX *ctx)
{
    size_t i, j;

    /* handle the padding */
    sm3_padding(ctx);

    /* the last iterator is handle the padding data */
    sm3_compress(ctx->digest, ctx->block);

    /* put the final value to out md */
    for (i = 0, j = 0; i < 8; ++i, j += 4) {
        PUT_LONG(md + j, ctx->digest[i]);
    }

    return 1;
}

static int init(EVP_MD_CTX *ctx)
{
    return SM3_Init((SM3_CTX *) ctx->md_data);
}

static int update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return SM3_Update((SM3_CTX *) ctx->md_data, data, count);
}

static int final(EVP_MD_CTX *ctx, unsigned char *md)
{
    return SM3_Final(md, (SM3_CTX *) ctx->md_data);
}

static const EVP_MD sm3_md = {
    nid_sm3,
    nid_sm2_with_sm3,
    SM3_DIGEST_LENGTH,
    EVP_MD_FLAG_PKEY_METHOD_SIGNATURE,
    init,
    update,
    final,
    NULL,
    NULL,
#if 0
    EVP_PKEY_ECDSA_method,
#else
    NULL,
    NULL,
    {0, 0, 0, 0},
#endif
    SM3_CBLOCK,
    sizeof(EVP_MD *) + sizeof(SM3_CTX),
    NULL
};

const EVP_MD *EVP_sm3(void)
{
    return &sm3_md;
}

/* @olen is input/oupt parameters */
static int sm3_one(unsigned char *in, size_t ilen, 
        unsigned char *out, size_t *olen)
{
    EVP_MD_CTX ctx;
    const EVP_MD *md = EVP_sm3();
    unsigned int mlen = (unsigned int) *olen;

    if (!in || !out || *olen < (size_t)EVP_MD_size(md)) {
        ERROR_MSG("parameters ERROR\n");
        return 0;
    }

    EVP_MD_CTX_init(&ctx);

    EVP_DigestInit(&ctx, md);
    EVP_DigestUpdate(&ctx, in, ilen);
    EVP_DigestFinal(&ctx, out, &mlen);

    EVP_MD_CTX_cleanup(&ctx);

    *olen = (size_t) mlen;

    return 1;
}

/* ==================== test begin ========================= */

/* the input data and results are comming from 
 * GM/T 0004-2012 A.1 && A.2 
 * */
static char *test[] = {
    "abc",
    "abcd" "abcd" "abcd" "abcd" "abcd" "abcd" "abcd" "abcd"
    "abcd" "abcd" "abcd" "abcd" "abcd" "abcd" "abcd" "abcd",
    NULL,
};

static char *ret[] = {
    "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
    "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
    NULL
};

int sm3_test(int argc, char *argv[])
{
    int i, err = 0;
    char **P, **R;
    char *s;
    unsigned char md[EVP_MAX_MD_SIZE];
    size_t mlen;

    P = test;
    R = ret;
    i = 1;

    while (*P != NULL) {
        mlen = sizeof (md);
        sm3_one((unsigned char *)*P, strlen((char *)*P), md, &mlen);
        s = hex2oct(md, mlen);
        if (strcmp(s, *R) != 0) {
            ERROR_MSG("%s ----------> testcase[%d] ERROR\n", __FUNCTION__, i);
            err++;
        } else {
            printf("%s ----------> testcase[%d] ok\n", __FUNCTION__, i);
        }

        i++;
        P++;
        R++;
    }

    if (err) {
        ERROR_MSG("test result %d failed\n", err);
    }

    return err;
}

