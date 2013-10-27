
#if !defined(SAD_SARP_H)
#define SAD_SARP_H

#include <pcap.h>
#include <libnet.h>

#include <sad_crypto.h>
#include <sad_inet.h>

/*
 * taken from sll.h in the libpcap source code 
 *
 * this is needed since we do a pcap_open_live on "any" device
 * and the packets are filled with this fake header
 */

/*
 * A DLT_LINUX_SLL fake link-layer header.
 */
#define SLL_HDR_LEN	16		/* total header length */
#define SLL_ADDRLEN	8		/* length of address field */

struct sll_header {
	u_int16_t sll_pkttype;		      /* packet type */
	u_int16_t sll_hatype;		      /* link-layer address type */
	u_int16_t sll_halen;		         /* link-layer address length */
	u_int8_t sll_addr[SLL_ADDRLEN];	/* link-layer address */
	u_int16_t sll_protocol;		      /* protocol */
};

/*
 * The LINUX_SLL_ values for "sll_pkttype"; these correspond to the
 * PACKET_ values on Linux, but are defined here so that they're
 * available even on systems other than Linux, and so that they
 * don't change even if the PACKET_ values change.
 */
#define LINUX_SLL_HOST		   0
#define LINUX_SLL_BROADCAST	1
#define LINUX_SLL_MULTICAST	2
#define LINUX_SLL_OTHERHOST	3
#define LINUX_SLL_OUTGOING	   4

/***** end of ssl.h *********/


struct fixed_ether_arp {
   struct libnet_arp_hdr arp_hdr;   /* fixed-size header */
   u_int8_t arp_sha[LL_ADDR_LEN];   /* sender hardware address */
   u_int8_t arp_spa[IP_ADDR_LEN];   /* sender protocol address */
   u_int8_t arp_tha[LL_ADDR_LEN];   /* target hardware address */
   u_int8_t arp_tpa[IP_ADDR_LEN];   /* target protocol address */
};

/*
 * here is the declaration of the Secure ARP header.
 * it will be after the common ARP header and will carry
 * authentication for all the replies
 */

struct sarp_auth_msg {
   u_int32  magic;
      #define SARP_MAGIC 0x7599e11e
   u_int8   type;
      #define SARPOP_SIGN           0x00     /* 0000 0000 */
      #define SARPOP_TIME_REQUEST   0x01     /* 0000 0001 */
      #define SARPOP_TIME_REPLY     0x02     /* 0000 0010 */
      #define SARPOP_KEY_REQUEST    0x04     /* 0000 0100 */
      #define SARPOP_KEY_REPLY      0x08     /* 0000 1000 */
      #define SARPOP_KEY_NOTFOUND   0x10     /* 0001 0000 */
      #define SARPOP_KEY_INVALID    0x20     /* 0010 0000 */
   u_int8   siglen;
   u_int16  datalen;
   u_int32  timestamp;
};

/*
 * special value for sarp operations.
 * use 0xff because other host not sarp enabled
 * must ignore this type of arp packets
 */

#define ARPOP_SARP   0xff

/*
 * max difference between timestamp
 * after which the signature is considered
 * invalid
 */

#define SARP_MAX_TIME_DIFF 60    /* in seconds */

extern void sarp_get(u_char *u, const struct pcap_pkthdr *pkthdr, const u_char *pkt);
extern int sarp_verify_sign(char *iface, struct libnet_arp_hdr *arp);

extern int sarp_check_timestamp(char *iface, u_int32 timestamp);

#endif

/* EOF */

// vim:ts=3:expandtab

