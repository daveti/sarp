/*
    sarpd -- iface and capture functions

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
#include <sys/socket.h>

#include <pcap.h>

#define PCAP_IFACE "any"
#define PCAP_FILTER "arp"
#define PCAP_PROMISC 0
#define PCAP_TIMEOUT 0

void capture_init(void);
void capture_close(void);
void capture(void);
void load_ifs(void);
void free_ifs(void);
int is_ether(char *iface);

/*******************************************/

/*
 * set up the pcap to capture only APR packet 
 * from all the devices
 */

void capture_init(void)
{
   pcap_t *pd;
   u_int32 net, mask;
   struct bpf_program bpf;
   char pcap_errbuf[PCAP_ERRBUF_SIZE];
   
   DEBUG_MSG("capture_init");
   
   GBL_PCAP->snaplen = 1500 + SLL_HDR_LEN;
   
   /*
    * set the offset of the link layer header to SLL_HDR_LEN
    * because we open "any" interface, our packet will have a fake
    * header... look in sad_sarp.h
    */

   GBL_PCAP->offset = SLL_HDR_LEN;
   
   pd = pcap_open_live(PCAP_IFACE, GBL_PCAP->snaplen, PCAP_PROMISC, 
                   PCAP_TIMEOUT, pcap_errbuf);
   ON_ERROR(pd, "%s", pcap_errbuf);
 
   if (pcap_lookupnet(PCAP_IFACE, &net, &mask, pcap_errbuf) == -1)
      ERROR_MSG("%s", pcap_errbuf);

   if (pcap_compile(pd, &bpf, PCAP_FILTER, 1, mask) < 0) 
      ERROR_MSG("%s", pcap_errbuf);
   
   if (pcap_setfilter(pd, &bpf) == -1) 
      ERROR_MSG("pcap_setfilter");
   
   GBL_PCAP->fd = pd;               
 
   atexit(capture_close);
   
   /*
    * and now fill the GBL_PCAP->ifs with the list of network interfaces
    */
   
   load_ifs();

}


void capture_close(void)
{
   pcap_close(GBL_PCAP->fd);
   
   sad_syslog("closed");
}


/*
 * start capturing packets
 */

void capture(void)
{
   DEBUG_MSG("neverending loop (capture)");
   
   /* 
    * infinite loop 
    * dispatch packets to sarp_get
    */
        
   pcap_loop(GBL_PCAP->fd, -1, sarp_get, NULL);
}


/*
 * check if an interface is an ethernet NIC or not
 */

int is_ether(char *iface)
{
   pcap_t *pd;
   char ebuf[PCAP_ERRBUF_SIZE];
   
   if ((pd = pcap_open_live(iface, 1500, PCAP_PROMISC, PCAP_TIMEOUT, ebuf)) == NULL)
      return 0;
  
   if ( pcap_datalink(pd) != DLT_EN10MB) {
      pcap_close(pd);
      return 0;
   }

   /* passed all the test, it is ethernet */
   pcap_close(pd);
   
   return 1;
}


/*
 * load the list of all interfaces the daemon will listen to
 */

void load_ifs(void)
{
   char ebuf[PCAP_ERRBUF_SIZE];
   pcap_if_t *prevdev, *curdev, *nextdev;
   pcap_addr_t *curaddr, *nextaddr;
   int to_free = 0;
   
   sad_syslog("listening on :");
   
   /*
    * load the list of all the inferfaces
    */
   
   if (pcap_findalldevs((pcap_if_t **)&GBL_PCAP->ifs, ebuf) == -1)
      ERROR_MSG("%s", ebuf);
   
   for (prevdev = curdev = (pcap_if_t *)GBL_PCAP->ifs; curdev != NULL; curdev = nextdev) {
      nextdev = curdev->next;
      to_free = 0;
      
      /*
       * remove the "any" and the loopback devides
       */
      
      if(!strcmp(curdev->name, "any") || !strcmp(curdev->name, "lo"))
         to_free = 1;
      
      /*
       * remove non ethernet devices
       */
      
      if(!is_ether(curdev->name))
         to_free = 1;
 
      /*
       * walk thru the addresses list
       */
      
      for (curaddr = curdev->addresses; curaddr != NULL; curaddr = nextaddr) {
         nextaddr = curaddr->next;
         
         if (!to_free) {
            // WE- don't worry about netmask for testing, it is not being populated
            // hardcoded in sad_inet.c
            //sad_syslog("%s : addr: 0x%08x netmask: 0x%08x", curdev->name, 
            sad_syslog("%s : addr: 0x%08x netmask: 0xffffff00", curdev->name, 
                           *(u_int32 *)&curaddr->addr->sa_data[2]);
//                           *(u_int32 *)&curaddr->netmask->sa_data[2]);
         } else {
            SAFE_FREE(curaddr->addr);
            SAFE_FREE(curaddr->netmask);
            SAFE_FREE(curaddr->broadaddr);
            SAFE_FREE(curaddr->dstaddr);
            SAFE_FREE(curaddr);
         }
      }
      
      if (to_free) {
         SAFE_FREE(curdev->name);
         SAFE_FREE(curdev->description);
         /*
          * relink the list with prevdev and nextdev
          */
         prevdev->next = nextdev;
         
         SAFE_FREE(curdev);
      } else {
         prevdev = curdev;
         GBL_PCAP->nifs++;
      }
   }

   if (GBL_PCAP->nifs == 0) {
      sad_syslog("no interface found. shutting down");
      exit(-1);
   }
  
   DEBUG_MSG("load_ifs: %d iface loaded", GBL_PCAP->nifs);
   
   atexit(free_ifs);     
}


void free_ifs(void)
{
   pcap_freealldevs((pcap_if_t *)GBL_PCAP->ifs);     
}

/* EOF */

// vim:ts=3:expandtab

