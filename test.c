#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "public.h"
#include "evp_sm3.h"
#include "ech_sm2.h"
#include "ecs_sm2.h"
#include "ece_sm2.h"

static const char rnd_seed[] = "string to make the random number";

int main(int argc, char *argv[])
{
    int ret;

    if (1) { /* open mem debug */
        CRYPTO_malloc_debug_init();
        CRYPTO_set_mem_debug_options(V_CRYPTO_MDEBUG_ALL);
    } else {
        CRYPTO_set_mem_debug_functions(0, 0, 0, 0, 0);
    }
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
	ERR_load_crypto_strings();
	RAND_seed(rnd_seed, sizeof rnd_seed); 

    ret = sm3_test(argc, argv);
    if (!ret) {
        DEBUG_MSG("sm3_test ........ OK\n");
    } else {
        DEBUG_MSG("sm3_test ........ ERROR\n");
    }

    ret = sm2_ecdh_test(argc, argv);
    if (!ret) {
        DEBUG_MSG("sm2_ecdh_test ........ OK\n");
    } else {
        DEBUG_MSG("sm2_ecdh_test ........ ERROR\n");
    }

    ret = sm2_ecdsa_test(argc, argv);
    if (!ret) {
        DEBUG_MSG("sm2_ecdsa_test ........ OK\n");
    } else {
        DEBUG_MSG("sm2_ecdsa_test ........ ERROR\n");
    }

    ret = sm2_ecies_test(argc, argv);
    if (!ret) {
        DEBUG_MSG("sm2_ecies_test ........ OK\n");
    } else {
        DEBUG_MSG("sm2_ecies_test ........ ERROR\n");
    }

    CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
	ERR_remove_state(0);
    CRYPTO_mem_leaks_fp(stderr);

    return 0;
}
