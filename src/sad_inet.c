
/*
    sarpd -- inet stuff

    Copyright (C) 2002  ALoR <alor@blackhats.it>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

*/

#include <sad_main.h>
#include <sad_sarp.h>
#include <sad_inet.h>

#include <libnet.h>

/* protos... */

int send_to_wire(char *iface, struct libnet_arp_hdr *arp);

char * ha_ntoa(const u_char *ll_addr);
char * ha_aton(const u_char *ll_addr);
char * pa_ntoa(const u_char *ip);
u_int32 pa_aton(const u_char *ip);

char * iface_ll_addr(char *iface);
u_int32 iface_ip_addr(char *iface);

int own_this_address(u_int32 addr, char **iface);
int belong_to_iface(u_int32 addr, char **iface);

/*******************************************/

//WL: used to initialize libnet context
extern libnet_t *l;
libnet_t * init_packet_injection(char *device,char *errbuf) 
{
  libnet_t *l;

  l = libnet_init(LIBNET_LINK_ADV,device,errbuf);                              
  return l;
}

int send_to_wire(char *iface, struct libnet_arp_hdr *arp)
{
   int c, len;

   //WL libnet init not needed with every send, l is moved as a global
   //libnet_t *l;

   libnet_ptag_t t;
   char errbuf[LIBNET_ERRBUF_SIZE];

// WE - not used
//   u_char *packet;
//   u_long packet_s;
   struct fixed_ether_arp *earp;
   struct sarp_auth_msg *sarp;
   
   DEBUG_MSG("send_to_wire %s", iface);
   
   //l = libnet_init(LIBNET_LINK_ADV, iface, errbuf);
   //ON_ERROR(l, "libnet fail: %s", errbuf);

   earp = (struct fixed_ether_arp *)arp;
   sarp = (struct sarp_auth_msg *)(earp+1);
   
   /*
    * create the sarp data
    */
   
   len = sizeof(struct sarp_auth_msg) + sarp->siglen + ntohs(sarp->datalen);
   
   DEBUG_MSG("send_to_wire: len = %d : %d %d %d", len, 
                   sizeof(struct sarp_auth_msg), 
                   ntohs(sarp->datalen), 
                   sarp->siglen);
   
   t = libnet_build_data((u_char *)sarp, len, l, 0);
   if (t == -1)
      ERROR_MSG("Can't build SARP header: %s\n", libnet_geterror(l));
   
   /*
    * create the ARP header
    */
   
   t = libnet_build_arp(
            ntohs(arp->ar_hrd),                     /* hardware addr */
            ntohs(arp->ar_pro),                     /* protocol addr */
            arp->ar_hln,                            /* hardware addr size */
            arp->ar_pln,                            /* protocol addr size */
            ntohs(arp->ar_op),                      /* operation type */
            earp->arp_sha,                          /* sender hardware addr */
            earp->arp_spa,                          /* sender protocol addr */
            earp->arp_tha,                          /* target hardware addr */
            earp->arp_tpa,                          /* target protocol addr */
            NULL,                                   /* payload */
            0,                                      /* payload size */
            l,                                      /* libnet handle */
            0);                                     /* libnet id */
   if (t == -1)
      ERROR_MSG("Can't build ARP header: %s\n", libnet_geterror(l));

   t = libnet_autobuild_ethernet(
            earp->arp_tha,                          /* ethernet destination */
            ETHERTYPE_ARP,                          /* protocol type */
            l);                                     /* libnet handle */
   if (t == -1)
      ERROR_MSG("Can't build ethernet header: %s\n", libnet_geterror(l));

   /*
    *  Write it to the wire.
    */

// WE - packet is never used
//   if (libnet_adv_cull_packet(l, &packet, &packet_s) == -1)
//      ERROR_MSG("libnet_adv_cull_packet: %s\n", libnet_geterror(l));

   if ((c = libnet_write(l)) == -1)
      ERROR_MSG("Write error: %s\n", libnet_geterror(l));
  
   //WL: using clear_packet instead of libnet destroy seems to improve performance
    libnet_clear_packet(l);  
   // libnet_destroy(l);
// WE - packet is never used
//   SAFE_FREE(packet);
  
   DEBUG_MSG("send_to_wire: total len 0x%04x", c);
   
   return c;
}


/*
 * convert a ip address to a printable dot notation
 */

char * pa_ntoa(const u_char *ip)
{
   return inet_ntoa(*(struct in_addr *)ip);
}

/*
 * convert a ip address in dot notation to interger
 */

u_int32 pa_aton(const u_char *ip)
{
   return inet_addr(ip);
}

/*
 * convert a link layer address to a printable colon separated format
 */

char * ha_ntoa(const u_char *ll_addr)
{
   static char printable[18];

   sprintf(printable, "%02X:%02X:%02X:%02X:%02X:%02X", ll_addr[0], ll_addr[1],
                   ll_addr[2], ll_addr[3], ll_addr[4], ll_addr[5]);
   
   return printable;
}

/*
 * convert a link layer address from ascii to network
 */

char * ha_aton(const u_char *ll_addr)
{
   static char network[LL_ADDR_LEN];
   int m1,m2,m3,m4,m5,m6;

   if (sscanf(ll_addr, "%02X:%02X:%02X:%02X:%02X:%02X", &m1, &m2, &m3, 
                           &m4, &m5, &m6) != 6)
      return NULL;
   
   network[0] = (char) m1;
   network[1] = (char) m2;
   network[2] = (char) m3;
   network[3] = (char) m4;
   network[4] = (char) m5;
   network[5] = (char) m6;
   
   return network;
}

/*
 * get the Link Layer address of the iface
 */

char * iface_ll_addr(char *iface)
{
   static char ll_addr[LL_ADDR_LEN];
   struct libnet_ether_addr *src;
   libnet_t *l;
   char errbuf[LIBNET_ERRBUF_SIZE];
 
   l = libnet_init(LIBNET_LINK, iface, errbuf);
   ON_ERROR(l, "libnet_init failed: %s", errbuf);
   
   src = libnet_get_hwaddr(l);
   
   memcpy(ll_addr, src->ether_addr_octet, LL_ADDR_LEN);

   libnet_destroy(l);
   
   return ll_addr;
}

/*
 * get the Link Layer address of the iface
 */

u_int32 iface_ip_addr(char *iface)
{
   pcap_if_t *curdev, *nextdev;
   pcap_addr_t *curaddr, *nextaddr;
   
   for (curdev = (pcap_if_t *)GBL_PCAP->ifs; curdev != NULL; curdev = nextdev) {
      nextdev = curdev->next;
      
      /*
       * walk thru the addresses list
       */
      
      for (curaddr = curdev->addresses; curaddr != NULL; curaddr = nextaddr) {
         nextaddr = curaddr->next;
       
         return *(u_int32 *)&curaddr->addr->sa_data[2];
      }
   }
   
   /*
    * on error return 0.0.0.0
    */
   
   return 0;
}


/*
 * find the iface in wich fall this address
 * return ESARP_SUCCESS on success and the name of the interface 
 *                      is malloced in char iface.
 *        -ESARP_NOTFOUND on failure and iface = NULL;
 */

int belong_to_iface(u_int32 addr, char **iface)
{
   pcap_if_t *curdev, *nextdev;
   pcap_addr_t *curaddr, *nextaddr;
   u_int32 netmask, network, address;
   
   for (curdev = (pcap_if_t *)GBL_PCAP->ifs; curdev != NULL; curdev = nextdev) {
      nextdev = curdev->next;
      
      /*
       * walk thru the addresses list
       */
      
      for (curaddr = curdev->addresses; curaddr != NULL; curaddr = nextaddr) {
         nextaddr = curaddr->next;
       
         // hard coded netmask for testing purposes 
         //netmask = *(u_int32 *)&curaddr->netmask->sa_data[2];
         netmask = htonl(0xffffff00);
         address = *(u_int32 *)&curaddr->addr->sa_data[2];
         network = address & netmask;
         
         if ((addr & netmask) == network) {
            *iface = strdup(curdev->name);
            return ESARP_SUCCESS;
         }
                 
      }
   }
   *iface = NULL;
   return -ESARP_NOTFOUND;
}

/*
 * check if the address is bound to one of my interfaces.
 * return ESARP_SUCCESS on success and the name of the interface 
 *                      is malloced in char iface.
 *        -ESARP_NOTFOUND on failure and iface = NULL;
 */

int own_this_address(u_int32 addr, char **iface)
{
   pcap_if_t *curdev, *nextdev;
   pcap_addr_t *curaddr, *nextaddr;
   
   for (curdev = (pcap_if_t *)GBL_PCAP->ifs; curdev != NULL; curdev = nextdev) {
      nextdev = curdev->next;
      
      /*
       * walk thru the addresses list
       */
      
      for (curaddr = curdev->addresses; curaddr != NULL; curaddr = nextaddr) {
         nextaddr = curaddr->next;
      
         if (addr == *(u_int32 *)&curaddr->addr->sa_data[2]) {
            *iface = strdup(curdev->name);
            return ESARP_SUCCESS;
         }
                 
      }
   }
   *iface = NULL;
   return -ESARP_NOTFOUND;
}


/* EOF */

// vim:ts=3:expandtab

