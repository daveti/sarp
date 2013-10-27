
#if !defined(SARP_ERROR_H)
#define SARP_ERROR_H


#include <errno.h>

extern void error_msg(char *file, char *function, int line, char *message, ...);

#define ERROR_MSG(x, args...) error_msg(__FILE__, __FUNCTION__, __LINE__, x, ## args)

#define ON_ERROR(x, fmt, args...) do { if (x == NULL) ERROR_MSG(fmt, ## args); } while(0)

#define EXIT_MSG(x, args...) do { printf("\n"x"\n\n", ##args); exit(1); } while(0);

#endif

/* EOF */

// vim:ts=3:expandtab

