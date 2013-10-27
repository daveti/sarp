
#if !defined(SAD_ERROR_H)
#define SAD_ERROR_H


#include <errno.h>

extern void error_msg(char *file, char *function, int line, char *message, ...);

#define ERROR_MSG(x, args...) error_msg(__FILE__, __FUNCTION__, __LINE__, x, ## args)

#define ON_ERROR(x, fmt, args...) do { if (x == NULL) ERROR_MSG(fmt, ## args); } while(0)


#define ESARP_SUCCESS      0
#define ESARP_FAILED       1
#define ESARP_NOTFOUND     2
#define ESARP_KEYMISMATCH  3
#define ESARP_IGNORE       4
#define ESARP_QUEUED       5
#define ESARP_REPLACED     6
#define ESARP_TIMEEXCEDED  7



#endif

/* EOF */

// vim:ts=3:expandtab

