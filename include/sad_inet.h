
#if !defined(SAD_INET_H)
#define SAD_INET_H

#define LL_ADDR_LEN 6   /* ethernet address len */
#define IP_ADDR_LEN 4   /* ip address len */

#define LL_ASCII_ADDR_LEN 17   /* ethernet address len in ascii format*/
#define IP_ASCII_ADDR_LEN 15   /* ip address len in asci format */

#include <sad_sarp.h>

extern int send_to_wire(char *iface, struct libnet_arp_hdr *arp);

extern char * ha_ntoa(const u_char *mac);
extern char * ha_aton(const u_char *ll_addr);
extern char * pa_ntoa(const u_char *ip);
extern u_int32 pa_aton(const u_char *ip);

extern char * iface_ll_addr(char *iface);
extern u_int32 iface_ip_addr(char *iface);

extern int own_this_address(u_int32 addr, char **iface);
extern int belong_to_iface(u_int32 addr, char **iface);

#endif

/* EOF */

// vim:ts=3:expandtab

