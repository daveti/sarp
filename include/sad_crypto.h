
#if !defined(SAD_CRYPTO_H)
#define SAD_CRYPTO_H

#include <sad_stdint.h>
#include <openssl/dsa.h>
#include <openssl/sha.h>

/* these are default values */

#define DFL_SIG_BIT_LEN         1024

extern void crypto_init(void);
extern void crypto_precomp(void);
extern void crypto_sign(u_char *data, int len, u_char *sign, u_int32 *siglen);
extern int crypto_verify_sign(u_char *data, int len, u_char *sig, int siglen, DSA *key);
extern void crypto_load_sarp_file(char *filename, u_int32 *ip_addr, u_char *ll_addr, DSA **dsa);

extern DSA * DSA_dup(DSA *src);

#include <sarp_crypto.h>

#endif

/* EOF */

// vim:ts=3:expandtab

