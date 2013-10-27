
#if !defined(SARP_CRYPTO_H)
#define SARP_CRYPTO_H


#include <sad_crypto.h>

extern void crypto_genkeypair(char **pub, char **priv);
extern int crypto_validate_keypair(char *pub, char *priv, char **correct);
extern void crypto_sign_info(char *message, char **sig);

#include <openssl/dsa.h>

#define LOAD_PRIV    0
#define LOAD_PUB     1

extern int crypto_load_file(char *filename, int type, DSA **dsa);

extern int b64_to_raw(char *b, u_char **r);
extern int raw_to_b64(char *r, int l, char **b);

#define SARP_FILE_FORMAT_STRING  "IP: %s\n" \
                                 "LL: %s\n" \
                                 "---BEGIN Secure ARP PUBLIC KEY---\n" \
                                 "%s" \
                                 "---END Secure ARP PUBLIC KEY---\n"


#endif

/* EOF */

// vim:ts=3:expandtab

