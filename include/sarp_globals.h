
#if !defined(SARP_GLOBALS_H)
#define SARP_GLOBALS_H

struct sarp_options {
   char genkey:1;
   char check:1;
   char sign:1;
   char verbose:1;
   int bitlen;
   char *file;
};

struct program_env {
   char *name;
   char *version;
};

struct globals {
   struct sarp_options *options;
   struct program_env *env;
};

extern struct globals *gbls;

#define GBLS gbls

#define GBL_OPTIONS (GBLS->options)
#define GBL_ENV (GBLS->env)

#define GBL_PROGRAM (GBL_ENV->name)
#define GBL_VERSION (GBL_ENV->version)

/* exported functions */

void globals_alloc(void);


#endif

/* EOF */

// vim:ts=3:expandtab

