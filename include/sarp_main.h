

#if !defined(SARP_MAIN_H)
#define SARP_MAIN_H


#ifdef HAVE_CONFIG_H
   #include <config.h>
#endif

#include <sys/types.h>
#include <sys/time.h>

#include <stdio.h>
#include <stdlib.h>
#if !defined (__USE_GNU)  /* for memmem(), strsignal(), etc etc... */
   #define __USE_GNU
#endif
#include <string.h>
#if defined (__USE_GNU)
   #undef __USE_GNU
#endif
#include <strings.h>
#include <unistd.h>
#include <missing/queue.h>
#include <sarp_error.h>
#include <sarp_globals.h>


#ifndef HAVE_STRLCAT
   #include <missing/strlcat.h>
#endif
#ifndef HAVE_STRLCPY 
   #include <missing/strlcpy.h>
#endif

#define SAFE_FREE(x) do{ if(x) { free(x); x = NULL; } }while(0)


#endif   /*  SARP_MAIN_H */

/* EOF */

// vim:ts=3:expandtab

