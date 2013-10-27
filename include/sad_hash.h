
#if !defined(SAD_HASH_H)
#define SAD_HASH_H

#define HASH_BIT       5                  /* 2^5 bit tab entries: 32 SLISTS */
#define HASH_SIZE      (1UL<<HASH_BIT)
#define HASH_MASK      (HASH_SIZE-1)      /* to mask fnv_1 hash algorithm */


inline unsigned long fnv_hash (const char *p, int s);
        
#endif

/* EOF */

// vim:ts=3:expandtab

