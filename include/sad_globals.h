
#if !defined(SAD_GLOBALS_H)
#define SAD_GLOBALS_H

#include <sad_inet.h>

struct sad_options {
   char ca_mode;
   char *prefix;
   char *conf_file;
   char *known_file;
};

struct program_env {
   char *name;
   char *version;
   char *debug_file;
};

struct pcap_env {
   void *fd;         /* this is a pcap_t */
   u_int16 offset;
   u_int16 snaplen;
   void *ifs;        /* this is a pcap_if (only 0.7.1 or greater) */
   int nifs;         /* number of ifaces */
};

struct crypto_env {
   int siglen;
   DSA *my_key;     /* this is the host key */
};

struct globals {
   struct sad_options *options;
   struct program_env *env;
   struct pcap_env *pcap;
   struct crypto_env *crypto;
};

extern struct globals *gbls;

#define GBLS gbls

#define GBL_OPTIONS        (GBLS->options)
#define GBL_ENV            (GBLS->env)
#define GBL_PCAP           (GBLS->pcap)
#define GBL_CRYPTO         (GBLS->crypto)

#define GBL_PROGRAM        (GBL_ENV->name)
#define GBL_VERSION        (GBL_ENV->version)
#define GBL_DEBUG_FILE     (GBL_ENV->debug_file)

#define GBL_PREFIX         (GBL_OPTIONS->prefix)

#define GBL_CRYPTO_KEY     (GBL_CRYPTO->my_key)
#define GBL_CRYPTO_SIGLEN  (GBL_CRYPTO->siglen)


/* exported functions */

void globals_alloc(void);


#endif

/* EOF */

// vim:ts=3:expandtab

