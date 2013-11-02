/*
    sarpd -- Secure ARP packet manipulation

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

#include <linux/if_ether.h>
#include <sad_main.h>
#include <sad_sarp.h>
#include <sad_inet.h>
#include <sad_conf.h>
#include <sad_neigh.h>
#include <sad_crypto.h>
#include <sad_key.h>

#include <pcap.h>
#include <libnet.h>

#include <ctype.h>
/* arphdr declaration */
#if 0
   struct libnet_arp_hdr {
      unsigned short int ar_hrd;          /* Format of hardware address.  */
      unsigned short int ar_pro;          /* Format of protocol address.  */
      unsigned char ar_hln;               /* Length of hardware address.  */
      unsigned char ar_pln;               /* Length of protocol address.  */
      unsigned short int ar_op;           /* ARP opcode (command).  */
   };

#define ARPOP_REQUEST   1               /* ARP request.  */
#define ARPOP_REPLY     2               /* ARP reply.  */
#define ARPOP_RREQUEST  3               /* RARP request.  */
#define ARPOP_RREPLY    4               /* RARP reply.  */
[...]
#define ARPHRD_ETHER    1               /* Ethernet 10/100Mbps.  */
[...]

#endif

/* ether_arp declaration */
#if 0
   struct  fixed_ether_arp {
      struct  arphdr ea_hdr;          /* fixed-size header */
      u_int8_t arp_sha[ETH_ALEN];     /* sender hardware address */
      u_int8_t arp_spa[4];            /* sender protocol address */
      u_int8_t arp_tha[ETH_ALEN];     /* target hardware address */
      u_int8_t arp_tpa[4];            /* target protocol address */
   };
#endif



/* protos... */

void sarp_get(u_char *u, const struct pcap_pkthdr *pkthdr, const u_char *pkt);
void sarp_reply(struct libnet_arp_hdr *sarp);
void sarp_sign(char *iface, struct libnet_arp_hdr *arp);
int sarp_verify_sign(char *iface, struct libnet_arp_hdr *arp);
int sarp_verify_ca_sign(char *iface, struct libnet_arp_hdr *arp);
        
void arp_request(struct libnet_arp_hdr *arp);
void arp_reply(struct libnet_arp_hdr *arp);
void sarp_operation(struct libnet_arp_hdr *arp);

void sarp_op_key_request(struct libnet_arp_hdr *arp);
void sarp_op_key_reply(struct libnet_arp_hdr *arp);
void sarp_op_time_request(struct libnet_arp_hdr *arp);
void sarp_op_time_reply(struct libnet_arp_hdr *arp);

int sarp_check_timestamp(char *iface, u_int32 timestamp);

/*******************************************/

void sarp_get(u_char *u, const struct pcap_pkthdr *pkthdr, const u_char *pkt)
{
   struct libnet_arp_hdr *arp;
   struct fixed_ether_arp *earp;
   struct sarp_auth_msg *sarp;
   u_char *buf;
   int len;
 
   DEBUG_MSG("\n***************************************************************\n");
   DEBUG_MSG("sarp_get (one packet dispatched from pcap)");
   
   DEBUG_MSG("CAPTURED: 0x%04x bytes\n%s\n", pkthdr->caplen,
                   hex_format(pkt, pkthdr->caplen));
   
   DEBUG_MSG("OOR: 0x%04x bytes\n%s\n", 64, 
                   hex_format(pkt + pkthdr->caplen, 64));

   arp = (struct libnet_arp_hdr *)(pkt + GBL_PCAP->offset);
   earp = (struct fixed_ether_arp *)arp;
   sarp = (struct sarp_auth_msg *)(earp + 1);

   
   /*
    * discard ARP request or reply not for ETHERNET OR IPv4
    *
    * XXX - this should be fixed in the future... since 
    * the kernel is no more responsible for those packets
    * we have to deal with devices other than ehternet
    */
   
   if (ntohs(arp->ar_hrd) != ARPHRD_ETHER)
      return;

   /*
    * XXX - this should support IPv6, but since the LKM
    * disable the receiption only for IPv4 we must deal 
    * only with this version.
    */
   
   if (ntohs(arp->ar_pro) != ETH_P_IP)
      return;
   
   /* do some sanity check */

   len = GBL_PCAP->offset +
         sizeof(struct fixed_ether_arp);
   
   if (sarp->magic == ntohl(SARP_MAGIC))
      len +=  sizeof(struct sarp_auth_msg) +
              ntohs(sarp->datalen) +
              sarp->siglen;

   if (len > pkthdr->caplen) {
      DEBUG_MSG("MALFORMED PACKET real 0x%04x virtual [0x%04x]", pkthdr->caplen, len);
      DEBUG_MSG("                 datalen %d siglen %d", ntohs(sarp->datalen), sarp->siglen);
      return;
   } else
      DEBUG_MSG("PCAP real 0x%04x virtual [0x%04x]", pkthdr->caplen, len);
           

   /* take actions */
   
   switch(ntohs(arp->ar_op)) {
      case ARPOP_REQUEST:
               arp_request(arp);    /* someone is asking for an address */
               break;
      case ARPOP_REPLY:

               if (sarp->magic == ntohl(SARP_MAGIC))
                  /*
                   * if the arp reply has the "magic" payload, 
                   * it is a S-ARP reply, checkit.
                   */
                  sarp_reply(arp); 
               else
                  arp_reply(arp);   /* someone is using old style ARP
                                     * check in the known_host file
                                     */
               break;
      case ARPOP_SARP:
               /*
                * this value is used for special communication
                * between the CA and the hosts.
                *
                * use a value of 0xff so other host not sarp enabled
                * will ingnore this type of packets.
                */
               if (sarp->magic == ntohl(SARP_MAGIC))
//daveti: debug
{
		printf("daveti: got SARP from CA\n");
                  sarp_operation(arp);
}
               
               break;
   }
   
   
   buf = (u_char *)pkt;
   memset(buf, 0, pkthdr->caplen);
}

/*
 * process a normal ARP request (old style)
 */

void arp_request(struct libnet_arp_hdr *arp)
{
   char *iface = NULL;
   struct fixed_ether_arp *earp;

   earp = (struct fixed_ether_arp *)arp;
   
   DEBUG_MSG("ARP REQUEST");
   DEBUG_MSG(" --> sha  %s", ha_ntoa(earp->arp_sha));
   DEBUG_MSG(" --> spa  %s", pa_ntoa(earp->arp_spa));
   DEBUG_MSG(" --> tha  %s", ha_ntoa(earp->arp_tha));
   DEBUG_MSG(" --> tpa  %s", pa_ntoa(earp->arp_tpa));

   if (own_this_address(*(u_int32 *)&earp->arp_tpa, &iface) == ESARP_SUCCESS) {
      u_char myaddr[arp->ar_pln];
      
      DEBUG_MSG("REQUEST FOR US -- 0x%08x on %s!!", *(u_int32 *)&earp->arp_tpa, iface);
      DEBUG_MSG("REPLYING -- %s %s on %s ", pa_ntoa(earp->arp_tpa),
                      ha_ntoa(iface_ll_addr(iface)),
                      iface);
   
      /* save my address */
      
      memcpy(myaddr, earp->arp_tpa, arp->ar_pln);     
      
      /*
       * swap the sender and the target
       * and change the ARPOP
       */
      
      memcpy(earp->arp_tha, earp->arp_sha, arp->ar_hln);
      memcpy(earp->arp_tpa, earp->arp_spa, arp->ar_pln);
      
      arp->ar_op = htons(ARPOP_REPLY);

      /* fill with my addresses */
      
      memcpy(earp->arp_sha, iface_ll_addr(iface), arp->ar_hln);
      memcpy(earp->arp_spa, myaddr, arp->ar_pln);
    
      /* 
       * sign my reply  
       * the buffer is 1500 byte, we can write after
       * the arp header
       */
      
      sarp_sign(iface, arp);
   
      /* send it */
      
      send_to_wire(iface, arp);
  
      /* 
       * precompute DSA parameter for the next signature 
       *
       * we can copute it at this time, because we have
       * sent the response to the wire.
       * in this way while the other hosts is performing 
       * its computation, we precalculate the signature
       * for the next time.
       */

      crypto_precomp();
   }
   
   SAFE_FREE(iface);

//daveti: debug
DEBUG_MSG("daveti: arp_request done");

}

/*
 * process a normal ARP reply (old style) == CAUTION
 */

void arp_reply(struct libnet_arp_hdr *arp)
{
   struct fixed_ether_arp *earp;
   char *iface = NULL;
   
   DEBUG_MSG("arp_reply");
   
   earp = (struct fixed_ether_arp *)arp;
   
   /*
    * the reply carry our address, we already have this
    */
   
   if (own_this_address(*(u_int32 *)&earp->arp_spa, &iface) == ESARP_SUCCESS) {
      SAFE_FREE(iface);
//daveti: debug
DEBUG_MSG("daveti: arp_reply ESARP_SUCCESS done");

      return;
   }
 
   /*
    * the reply is not for us
    */
   
   if (own_this_address(*(u_int32 *)&earp->arp_tpa, &iface) == -ESARP_NOTFOUND)
//daveti: debug
{
DEBUG_MSG("daveti: arp_reply ESARP_NOTFOUND done");
      return;
}
  
   SAFE_FREE(iface);
   
   /*
    * is the sender on any of my iface ?
    */
   
   if (belong_to_iface(*(u_int32 *)&earp->arp_spa, &iface) == -ESARP_NOTFOUND) 
//daveti: debug
{
DEBUG_MSG("daveti: arp_reply belog to ESARP_NOTFOUND done");
      return;
}
   
   DEBUG_MSG("ARP REPLY");
   DEBUG_MSG(" --> sha  %s", ha_ntoa(earp->arp_sha));
   DEBUG_MSG(" --> spa  %s", pa_ntoa(earp->arp_spa));
   DEBUG_MSG(" --> tha  %s", ha_ntoa(earp->arp_tha));
   DEBUG_MSG(" --> tpa  %s", pa_ntoa(earp->arp_tpa));
   
   /*
    * check if <MAC,IP> is present in the known_host
    * this is a sort of compatibility mode against
    * hosts that don't support SARP
    */
        
   if (search_known_hosts(earp->arp_sha, *(u_int32 *)&earp->arp_spa) == ESARP_SUCCESS) {
      /*
       * insert the entry in the neigbor system
       */
           
      neigh_add(earp->arp_sha, *(u_int32 *)&earp->arp_spa, iface, NUD_REACHABLE);
      
   } else {
      DEBUG_MSG("UNAUTHORIZED ARP REPLY -- %s %s on %s", pa_ntoa(earp->arp_spa), 
                   ha_ntoa(earp->arp_sha),
                   iface);
   }
           
   SAFE_FREE(iface);

//daveti: debug
DEBUG_MSG("daveti: arp_reply done");

}

/*
 * validate a Secure ARP reply 
 */

void sarp_reply(struct libnet_arp_hdr *arp)
{
   struct fixed_ether_arp *earp;
   char *iface = NULL;
    
   DEBUG_MSG("sarp_reply");
   
   earp = (struct fixed_ether_arp *)arp;
  
   /*
    * the reply is not for us
    */
   
   if (own_this_address(*(u_int32 *)&earp->arp_tpa, &iface) == -ESARP_NOTFOUND)
      return;
   
   SAFE_FREE(iface);
   
   /*
    * is the sender on any of my iface ?
    */
   
   if (belong_to_iface(*(u_int32 *)&earp->arp_spa, &iface) == -ESARP_NOTFOUND) 
      return;

   DEBUG_MSG("S-ARP REPLY");
   DEBUG_MSG(" --> sha  %s", ha_ntoa(earp->arp_sha));
   DEBUG_MSG(" --> spa  %s", pa_ntoa(earp->arp_spa));
   DEBUG_MSG(" --> tha  %s", ha_ntoa(earp->arp_tha));
   DEBUG_MSG(" --> tpa  %s", pa_ntoa(earp->arp_tpa));
           
   /* verify if the reply is correctly signed */
   
   switch( sarp_verify_sign(iface, arp) ) {
      case -ESARP_KEYMISMATCH:
               sad_syslog("SIGNATURE MISMATCH: ASKING NEW KEY : %s %s", 
                           ha_ntoa(earp->arp_sha), 
                           pa_ntoa(earp->arp_spa));

               SAFE_FREE(iface);
               
               /*
                * if we are the CA, there is nothting to do...
                * the signature is INCORRECT.
                */
               
               if (GBL_OPTIONS->ca_mode) {
                  sad_syslog("WARNING: %s is NOT correctly signed !", pa_ntoa(earp->arp_spa) );
                  return;
               }
               
               /*
                * ask a new key to the CA.
                * do that because the key may have been changed
                * for some reasons.
                * if the cached one is the same, then reject, 
                * else update the cached key
                */
               
               key_queue_add(earp);
               key_request(*(u_int32 *)&earp->arp_spa);
               
               return;
               break;
               
      case ESARP_SUCCESS:
               /* add the entry in the neigh table of the proper iface */
               neigh_add(earp->arp_sha, *(u_int32 *)&earp->arp_spa, iface, NUD_REACHABLE);
               SAFE_FREE(iface);
               return;
               break;
               
      case -ESARP_IGNORE:
      case -ESARP_QUEUED:
      default:
               /* 
                * the packet has to be ingored.
                * it is invalid or queued
                */
               SAFE_FREE(iface);
               return;
               break;
   }
   
}

/****************************************************************/

/*
 * add the signature to a packet
 */


void sarp_sign(char *iface, struct libnet_arp_hdr *arp)
{
   u_int32 siglen;
   struct fixed_ether_arp *earp;
   struct sarp_auth_msg *sarp;
    
   earp = (struct fixed_ether_arp *)arp;
   sarp = (struct sarp_auth_msg *)(earp + 1);
  
   memset((u_char *)sarp, 0, sizeof(struct sarp_auth_msg));
   
   sarp->magic = htonl(SARP_MAGIC);
   sarp->type = SARPOP_SIGN;

   /*
    * sign only the sender hardware address and protocol address
    */
   
   sarp->siglen = 0;
   sarp->timestamp = htonl(get_timestamp(iface));
   sarp->datalen = 0;
   
   crypto_sign( (u_char *)(arp), sizeof(struct fixed_ether_arp) + 
                   sizeof(struct sarp_auth_msg), (u_char *)(sarp + 1), &siglen );

   sarp->siglen = (u_int8) siglen;
   
   DEBUG_MSG("sarp_sign: datalen %d siglen %d", ntohs(sarp->datalen), sarp->siglen);
   DEBUG_MSG("SIGNATURE:\n%s", hex_format((u_char *)(sarp+1), sarp->siglen) );
      
}

/*
 * check if the signature is correct
 * return:  ESARP_SUCCESS if correct
 *          -ESARP_KEYMISMATCH if incorrect
 *          -ESARP_IGNORE if the packet is to be ingored
 *          -ESARP_QUEUE if the packet was added to the queue
 *                       and a key was requested to the CA
 */

int sarp_verify_sign(char *iface, struct libnet_arp_hdr *arp)
{
   DSA *key = NULL;
   int ret, siglen;
   struct fixed_ether_arp *earp;
   struct sarp_auth_msg *sarp;
    
   earp = (struct fixed_ether_arp *)arp;
   sarp = (struct sarp_auth_msg *)(earp + 1);
        
   /* without the magic we can't be a spellcaster ;) */
        
   if (sarp->magic != ntohl(SARP_MAGIC))
      return -ESARP_IGNORE;

   /* this is not a signed message */
   
   if (sarp->type != SARPOP_SIGN)
      return -ESARP_IGNORE;
   
   /* check for the timestamp */

   if (sarp_check_timestamp(iface, ntohl(sarp->timestamp)) == -ESARP_TIMEEXCEDED) {
      sad_syslog("%s is replying with invalid timestamp", pa_ntoa(earp->arp_spa));
      return -ESARP_IGNORE;
   }
   
   /* 
    * get the key associated with that ip 
    * if a key cant be found put the packet in
    * the queue and return ignore.
    *
    * as the key arrives process the entries in 
    * the queue and validate them
    */
   
   if (get_key(*(u_int32 *)&earp->arp_spa, &key) == -ESARP_NOTFOUND ) {
     
      if (GBL_OPTIONS->ca_mode) {
         sad_syslog("I'm the CA and %s is not in the hosts list !", pa_ntoa(earp->arp_spa) );
         return -ESARP_IGNORE;
      }
              
      key_queue_add(earp);
      key_request(*(u_int32 *)&earp->arp_spa);
      
      return -ESARP_QUEUED;
   }
  
   /* 
    * the signature was made with the 
    * siglen equal to zero, we have to check
    * it with siglen as it was signed.
    * so we save the value and set the field 
    * to zero
    */
   
   siglen = sarp->siglen;
   sarp->siglen = 0;
   
   /*
    * verify only the sender hardware address and protocol address
    */
   
   DEBUG_MSG("sarp_verify_sign: datalen %d siglen %d", ntohs(sarp->datalen), siglen);
   DEBUG_MSG("VERIFIY:\n%s", hex_format((u_char *)(sarp+1), siglen) );
   
   ret = crypto_verify_sign( (u_char *)(arp), sizeof(struct fixed_ether_arp) + 
                   sizeof(struct sarp_auth_msg), (u_char *)(sarp + 1), siglen, key );

   /* 
    * if the signature is not correct the
    * packet will be queued and a new key is requested.
    * the queue_scan function must know the siglen,
    * so we have to restore the correct value in the packet.
    */
   
   sarp->siglen = siglen;
  
   DSA_free(key);
   
   return ret;
}

/*
 * verify the CA signature
 */

int sarp_verify_ca_sign(char *iface, struct libnet_arp_hdr *arp)
{
   DSA *dsa;
   struct fixed_ether_arp *earp;
   struct sarp_auth_msg *sarp;
   int slen, siglen, ret;
    
   earp = (struct fixed_ether_arp *)arp;
   sarp = (struct sarp_auth_msg *)(earp + 1);
  
   DEBUG_MSG("sarp_verify_ca_sign");
   
   /* get the CA key */
   
   if (get_ca_key(iface, NULL, NULL, &dsa) == -ESARP_NOTFOUND) {
      sad_syslog("We don't have the key for the CA on %s", iface );
      return -ESARP_NOTFOUND;
   }
  
   
   /* compute the size of the data */
   slen =  sizeof(struct fixed_ether_arp) + 
           sizeof(struct sarp_auth_msg) +
           ntohs(sarp->datalen);
   
   /*
    * the sender has signed with siglen equal to ZERO
    * so replace the value and check the signature
    */
   
   siglen = sarp->siglen;
   sarp->siglen = 0;
   
   DEBUG_MSG("sarp_verify_ca_sign: slen %d datalen %d siglen %d", slen, ntohs(sarp->datalen), siglen);
   DEBUG_MSG("VERIFY:\n%s", hex_format((u_char *)(sarp+1) + ntohs(sarp->datalen), siglen) );
   
   ret = crypto_verify_sign((u_char *)arp, slen, (u_char *)(sarp + 1) + 
                           ntohs(sarp->datalen), siglen, dsa);

   sarp->siglen = siglen;
   
   /* adjust the timestamp delta if the signature is ok */
   if (ret == ESARP_SUCCESS)
      ca_set_delta(iface, ntohl(sarp->timestamp));
  
   DSA_free(dsa);

   return ret;
}


/****************************************************************/

/*
 * handle all the sarp operations
 * such as KEY management and TIME syncornization
 */

void sarp_operation(struct libnet_arp_hdr *arp)
{
   struct fixed_ether_arp *earp;
   struct sarp_auth_msg *sarp;
    
   earp = (struct fixed_ether_arp *)arp;
   sarp = (struct sarp_auth_msg *)(earp + 1);
   
   DEBUG_MSG("SARP OPERATION");
   DEBUG_MSG(" --> sha       %s", ha_ntoa(earp->arp_sha));
   DEBUG_MSG(" --> spa       %s", pa_ntoa(earp->arp_spa));
   DEBUG_MSG(" --> tha       %s", ha_ntoa(earp->arp_tha));
   DEBUG_MSG(" --> tpa       %s", pa_ntoa(earp->arp_tpa));
   DEBUG_MSG(" --> magic     0x%08x", ntohl(sarp->magic) );
   DEBUG_MSG(" --> type      0x%02x", sarp->type);
   DEBUG_MSG(" --> datalen   %d", ntohs(sarp->datalen));
   DEBUG_MSG(" --> siglen    %d", sarp->siglen);
   DEBUG_MSG(" --> timestamp %u", ntohl(sarp->timestamp));
  
   
   switch (sarp->type) {
      case SARPOP_KEY_REQUEST:
         DEBUG_MSG("SARPOP_KEY_REQUEST");   
         sarp_op_key_request(arp);
         break;
              
      case SARPOP_KEY_REPLY:
      case SARPOP_KEY_REPLY | SARPOP_KEY_NOTFOUND:
         DEBUG_MSG("SARPOP_KEY_REPLY");     
         sarp_op_key_reply(arp);
         break;
         
      case SARPOP_TIME_REQUEST:
         DEBUG_MSG("SARPOP_TIME_REQUEST");   
         sarp_op_time_request(arp);
         break;
         
      case SARPOP_TIME_REPLY:
         DEBUG_MSG("SARPOP_TIME_REPLY");   
         sarp_op_time_reply(arp);
         break;
   }
   
}

/*
 * reply to a key request
 * only for the CA
 */

void sarp_op_key_request(struct libnet_arp_hdr *arp)
{
   DSA *dsa;
   char *iface = NULL;
   u_int32 siglen, slen, ip_addr;
   u_char *data;
   struct fixed_ether_arp *earp;
   struct sarp_auth_msg *sarp;
    
   earp = (struct fixed_ether_arp *)arp;
   sarp = (struct sarp_auth_msg *)(earp + 1);

   DEBUG_MSG("sarp_op_key_request");
   
   /* some sanity check */

   if (!GBL_OPTIONS->ca_mode) {
      sad_syslog("%s is asking me a key, but I'm not the CA", pa_ntoa(earp->arp_spa) );
      return;
   }
   
   /*
    * arp_spa is the address of the querier
    * arp_tpa is the address he is asking for
    */
   
   ip_addr = *(u_int32 *)&earp->arp_tpa;
   
   if (belong_to_iface(ip_addr, &iface) == -ESARP_NOTFOUND)
      return;

   /* prepare the reply */
   
   memcpy(earp->arp_tha, earp->arp_sha, LL_ADDR_LEN);
   memcpy(earp->arp_tpa, earp->arp_spa, IP_ADDR_LEN);
   
   memset(earp->arp_sha, 0, LL_ADDR_LEN);                 /* the sha doesn't care */
   memcpy(earp->arp_spa, (char *)&ip_addr, IP_ADDR_LEN);  /* the requested ip */
   
   /*
    * it is plenty of room here... ;)
    * a pachet dispatched from libpcap is 1500 byte
    * so we can write right after sarp
    */
   
   data = (u_char *)(sarp + 1);
   
   /* retrive the appropriate key */
   if (get_key(ip_addr, &dsa) == ESARP_SUCCESS) {
      sarp->type = SARPOP_KEY_REPLY;
      /* put the binary Public Key in the right buffer */
      sarp->datalen = htons(i2d_DSAPublicKey(dsa, &data));
      DEBUG_MSG("sarp_op_key_request: success");
   } else {
      sarp->type = SARPOP_KEY_REPLY | SARPOP_KEY_NOTFOUND;
      sarp->datalen = 0;
      DEBUG_MSG("sarp_op_key_request: NOT FOUND");
   }
   
   /* compute the size of the data to digest */
   slen =  sizeof(struct fixed_ether_arp) + 
           sizeof(struct sarp_auth_msg) +
           ntohs(sarp->datalen);

   /* 
    * sign the packet with this value equal to ZERO 
    * the verifier should change it before checking the sign
    */
   
   sarp->siglen = 0;
   
   sarp->timestamp = htonl(get_timestamp(iface));
   
   /* 
    * sign the reply 
    *
    * data is automatically updated by i2d_DSAPublicKey
    * and point to the the buffer for signature (right
    * after the key)
    */
   
   crypto_sign((u_char *)arp, slen, data, &siglen );

   DEBUG_MSG("sarp_op_key_request: slen %d datalen %d siglen %d", slen, ntohs(sarp->datalen), siglen);
   DEBUG_MSG("SIGNATURE:\n%s", hex_format(data, siglen) );
   
   /* append the real siglen */
   sarp->siglen = (u_int8) siglen;
   
   /* send it */
   send_to_wire(iface, arp);

   /* 
    * precompute DSA parameter for the next signature 
    *
    * we can copute it at this time, because we have
    * sent the response to the wire.
    * in this way while the other hosts is performing 
    * its computation, we precalculate the signature
    * for the next time.
    */
   crypto_precomp();

   /* free the whole data */
   
   SAFE_FREE(iface);
   DSA_free(dsa);
}


/*
 * get the reply and search for pending 
 * requests
 */

void sarp_op_key_reply(struct libnet_arp_hdr *arp)
{
   struct fixed_ether_arp *earp;
   struct sarp_auth_msg *sarp;
   char *iface = NULL;
   DSA *key;
   u_char *ptr;
    
   DEBUG_MSG("sarp_op_key_reply");
   
   earp = (struct fixed_ether_arp *)arp;
   sarp = (struct sarp_auth_msg *)(earp + 1);
   
   /*
    * arp_spa is the address of the querier
    * arp_tpa is the address he is asking for
    */
   
   if (belong_to_iface(*(u_int32 *)&earp->arp_spa, &iface) == -ESARP_NOTFOUND) {
      sad_syslog("BUG: CA has sent %s, but its not on our iface !", pa_ntoa(earp->arp_spa) );
      return;
   }
   
   /*
    * verify if it is correctly signed
    */
   
   if (sarp_verify_ca_sign(iface, arp) == -ESARP_KEYMISMATCH) {
      sad_syslog("CA[%s] reply incorrectly signed !!", iface);
      SAFE_FREE(iface);
      return;
   }
   
   SAFE_FREE(iface);
   
   /* do the CA has the KEY ? */
   
   if ((sarp->type & SARPOP_KEY_NOTFOUND) != 0) {

      /* 
       * the was not found, alert the user
       */
           
      sad_syslog("%s is not registered on the CA", pa_ntoa(earp->arp_spa) );

      /*
       * we can try to check if it is in the known_host file...
       * handle it as a normal arp_reply, the function will do the job
       */

      arp_reply(arp);
      
      return;
   }

   /* extract the key from the reply */
   ptr = (u_char *)(sarp + 1);
   
   if ( (key = d2i_DSAPublicKey(NULL, &ptr, ntohs(sarp->datalen) )) == NULL)
      return;
   
   /* add the key to de database */
   key_add(*(u_int32 *)&earp->arp_spa, key);
   
   /* scan the queue for pending packets */
   key_queue_scan(earp);
   
   DSA_free(key);
}


/*
 * handle a time request (only for the CA)
 */

void sarp_op_time_request(struct libnet_arp_hdr *arp)
{
   char *iface = NULL;
   u_int32 siglen, slen;
   struct fixed_ether_arp *earp;
   struct sarp_auth_msg *sarp;
   u_char myaddr[IP_ADDR_LEN];
    
   DEBUG_MSG("sarp_op_time_request");
   
   earp = (struct fixed_ether_arp *)arp;
   sarp = (struct sarp_auth_msg *)(earp + 1);

   /* not the CA, ignore this request */
   
   if (!GBL_OPTIONS->ca_mode)
      return;
   
   /* not on our ifaces */
   
   if (belong_to_iface(*(u_int32 *)&earp->arp_tpa, &iface) == -ESARP_NOTFOUND)
      return;

   /* prepare the reply */
   memcpy(myaddr, earp->arp_tpa, IP_ADDR_LEN);
   
   memcpy(earp->arp_tha, earp->arp_sha, LL_ADDR_LEN);
   memcpy(earp->arp_tpa, earp->arp_spa, IP_ADDR_LEN);
   
   memset(earp->arp_sha, 0, LL_ADDR_LEN); /* the sha doesn't care */
   memcpy(earp->arp_spa, myaddr, IP_ADDR_LEN);
   
   /* compute the size of the data to digest */
   slen =  sizeof(struct fixed_ether_arp) + 
           sizeof(struct sarp_auth_msg);

   /* 
    * sign the packet with this value equal to ZERO 
    * the verifier should change it before checking the sign
    */
   
   sarp->siglen = 0;
   
   sarp->timestamp = htonl(get_timestamp(iface));
   
   sarp->type = SARPOP_TIME_REPLY;
  
   sarp->datalen = 0;
   
   /* 
    * sign the reply 
    *
    * data is automatically updated by i2d_DSAPublicKey
    * and point to the the buffer for signature
    */
   
   crypto_sign((u_char *)arp, slen, (u_char *)(sarp + 1), &siglen );

   DEBUG_MSG("sarp_op_time_request: slen %d datalen %d siglen %d", slen, ntohs(sarp->datalen), siglen);
   DEBUG_MSG("SIGNATURE:\n%s", hex_format((u_char *)(sarp + 1), siglen) );
   
   /* append the real siglen */
   sarp->siglen = (u_int8) siglen;
   
   /* send it */
   send_to_wire(iface, arp);

   /* 
    * precompute DSA parameter for the next signature 
    *
    * we can copute it at this time, because we have
    * sent the response to the wire.
    * in this way while the other hosts is performing 
    * its computation, we precalculate the signature
    * for the next time.
    */
   crypto_precomp();

   /* free the whole data */
   
   SAFE_FREE(iface);
}

/*
 * store the timestamp from the CA
 * reset the alarm timer
 */

void sarp_op_time_reply(struct libnet_arp_hdr *arp)
{
   static int nifs = 0;
   struct fixed_ether_arp *earp;
   struct sarp_auth_msg *sarp;
   char *iface = NULL;
    
   earp = (struct fixed_ether_arp *)arp;
   sarp = (struct sarp_auth_msg *)(earp + 1);
   
   DEBUG_MSG("sarp_op_time_reply");
   
   if (belong_to_iface(*(u_int32 *)&earp->arp_spa, &iface) == -ESARP_NOTFOUND) {
      sad_syslog("BUG: non existent CA address: %s", pa_ntoa(earp->arp_spa) );
      return;
   }
   
   /*
    * verify if it is correctly signed
    */
   
   if (sarp_verify_ca_sign(iface, arp) == -ESARP_KEYMISMATCH) {
      sad_syslog("CA[%s] reply incorrectly signed !!", iface);
      SAFE_FREE(iface);
      return;
   }
   
   SAFE_FREE(iface);
   
   nifs++;

   if (nifs == GBL_PCAP->nifs) {
      signal(SIGALRM, SIG_IGN);
      DEBUG_MSG("All the %d CA(s) are up and running", GBL_PCAP->nifs);
   }
   
}


/****************************************************************/


/*
 * check if the timestamp is valid
 * returns -ESARP_TIMEEXCEDED if failed
 *          ESARP_SUCCESS if good
 */

int sarp_check_timestamp(char *iface, u_int32 timestamp)
{
        
   DEBUG_MSG("sarp_check_timestamp: %d [%d]", get_timestamp(iface) - timestamp, 
                   SARP_MAX_TIME_DIFF/2 );
   
   /*
    * SARP_MAX_TIME_DIFF is the permitted delta,
    * we have to check it half in the future
    * and half in the past...
    */
   
   if ( abs(get_timestamp(iface) - timestamp) > SARP_MAX_TIME_DIFF/2 )
      return -ESARP_TIMEEXCEDED;
   
   return ESARP_SUCCESS;
}

/* EOF */

// vim:ts=3:expandtab

