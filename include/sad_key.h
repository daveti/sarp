
#if !defined(SAD_KEY_H)
#define SAD_KEY_H

#include <openssl/dsa.h>

extern int get_key( u_int32 ip, DSA **key);
extern void key_queue_add(struct fixed_ether_arp *earp);
extern void key_queue_scan(struct fixed_ether_arp *earp);
extern void key_request(u_int32 ip);
extern int key_add(u_int32 ip, DSA *key);
extern void ca_add(char *iface, u_int32 ip, u_char *ll, DSA *key);
extern int get_ca_key(char *iface, u_int32 *ip_addr, u_char *ll_addr, DSA **key);

extern void send_time_request(void);
extern u_int32 get_timestamp(char *iface);
extern void ca_set_delta(char *iface, u_int32 ca_time);


#endif

/* EOF */

// vim:ts=3:expandtab

