/* Copyright (C) lnwdl (lnwdl@163.com)
 * All rights reserved.
 *
 * SM3 digest EVP.
 */

#ifndef __EVP_SM3_H__
#define __EVP_SM3_H__

#include <openssl/evp.h>

const EVP_MD *EVP_sm3(void);

int sm3_test(int argc, char *argv[]);

#endif
