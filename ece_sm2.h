/* Copyright (C) lnwdl (lnwdl@163.com)
 * All rights reserved.
 *
 * SM2 ecies.
 *
 * we know that ECIES not an atomic method, it a combine of ECDH, CIPHER,
 *  and HMAC operation.
 * First , use ECDH to generate a symmetric key,
 *  then, use the symmetric key to encrypt the input message.
 *  finally, compute a hmac to protect message integrity.
 */

#ifndef __ECE_SM2_H__
#define __ECE_SM2_H__

#include <openssl/ec.h>
#include <openssl/bn.h>

unsigned char *sm2_encrypt(const unsigned char *in, const size_t ilen,
        EC_KEY *eckey,          /* local private key */
        const BIGNUM *l_rnd,    /* local random */
        const EC_POINT *r_pub,  /* remote public key */
        size_t *olen);          /* out length */

unsigned char *sm2_decrypt(const unsigned char *in, const size_t ilen,
        EC_KEY *eckey,          /* local private key */
        size_t *olen);          /* out length */

int sm2_ecies_test(int argc, char *argv[]);

#endif
