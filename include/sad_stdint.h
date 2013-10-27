
#if !defined(SAD_STDINT_H)
#define SAD_STDINT_H

#ifdef HAVE_STDINT_H

	#include <stdint.h>

	typedef int8_t    int8;
	typedef int16_t   int16;
	typedef int32_t   int32;
	typedef int64_t   int64;

	typedef uint8_t   u_int8;
	typedef uint16_t  u_int16;
	typedef uint32_t  u_int32;
	typedef uint64_t  u_int64;

#else

   #include <sys/types.h>

	typedef int8_t    int8;
	typedef int16_t   int16;
	typedef int32_t   int32;
	typedef int64_t   int64;

	typedef u_int8_t   u_int8;
	typedef u_int16_t  u_int16;
	typedef u_int32_t  u_int32;
	typedef u_int64_t  u_int64;
   
#endif


#endif

/* EOF */

// vim:ts=3:expandtab
