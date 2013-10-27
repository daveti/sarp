
#if defined (DEBUG) && !defined(SAD_DEBUG_H)
#define SAD_DEBUG_H

extern void debug_init(void);
extern void debug_msg(char *message, ...);
extern char * hex_format(const u_char *buffer, int buff_len);

#define DEBUG_INIT() debug_init()
#define DEBUG_MSG(x, args...) debug_msg(x, ## args)

# define timersub(a, b, result) do {                 \
   (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;     \
   (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;  \
   if ((result)->tv_usec < 0) {                      \
      --(result)->tv_sec;                            \
      (result)->tv_usec += 1000000;                  \
   }                                                 \
} while (0)


#define DEBUG_TIME_DECLARATION struct timeval init_time, fini_time;
#define DEBUG_TIME_INIT() gettimeofday(&init_time, 0)
#define DEBUG_TIME_PRINT(x) do { \
   struct timeval total; \
   gettimeofday(&fini_time, 0); \
   timersub(&fini_time, &init_time, &total); \
   DEBUG_MSG(x " %d sec %ld usec", total.tv_sec, total.tv_usec ); \
} while(0)

#endif /* EC_DEBUG_H */

/* 
 * if DEBUG is not defined we expand the macros to null instructions...
 */

#ifndef DEBUG
   #define DEBUG_INIT()
   #define DEBUG_MSG(x, args...)
   #define DEBUG_TIME_DECLARATION
   #define DEBUG_TIME_INIT()
   #define DEBUG_TIME_PRINT(x)
#endif

/* EOF */

// vim:ts=3:expandtab

