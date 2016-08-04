/* Copyright (C) lnwdl (lnwdl@163.com)
 * All rights reserved.
 *
 * SM2 ECDSA_METHOD.
 *
 * Note: In openssl project, the input of sign/verify is the result of digest,
 *  and the input of digest is original message.
 * But in GM specification, the input of sign/verify is the original message,
 *  so you can't use the ECDSA_sm2 method in openssl directly.
 */

#ifndef __ECS_SM2_H__
#define __ECS_SM2_H__

#include <openssl/opensslv.h>
#include <openssl/ecdsa.h>

# if OPENSSL_VERSION_NUMBER < 0x10002000L
const ECDSA_METHOD *ECDSA_sm2(void);
# else
ECDSA_METHOD *ECDSA_sm2(void);
# endif

int sm2_ecdsa_test(int argc, char *argv[]);

#endif
