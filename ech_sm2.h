/* Copyright (C) lnwdl (lnwdl@163.com)
 * All rights reserved.
 *
 * SM2 ecdh.
 *
 * Note: In openssl project, the input parameters of ecdh is not so many.
 *  the sm2_compute_key is used in Gm SSL VPN protocol.
 */

#ifndef __ECH_SM2_H__
#define __ECH_SM2_H__

#include <openssl/bn.h>
#include <openssl/ec.h>

int sm2_compute_key(void *out, size_t outlen, 
        EC_KEY *eckey, const BIGNUM *rnd, const char *id,   /* local */
        const EC_POINT *r_pubrnd,                       /* remote*/ 
        const EC_POINT *r_pubkey, 
        const char *r_id,
        int is_initiator); /* is initiator or not */

int sm2_ecdh_test(int argc, char *argv[]);

#endif
