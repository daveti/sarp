
#if !defined(SAD_NEIGH_H)
#define SAD_NEOGH_H

#include <netinet/ip.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>


extern void neigh_disable_kernel(void);
extern void neigh_enable_kernel(void);
extern void neigh_flush_all_tables(void);
extern void neigh_add(char *ll_addr, u_int32 ip, char *iface, int nud);
extern void neigh_remove(char *ll_addr, u_int32 ip, char *iface);

#endif

/* EOF */

// vim:ts=3:expandtab

