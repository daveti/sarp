/*
    sarpd -- key management module

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
#include <sad_neigh.h>
#include <sad_sarp.h>
#include <sad_crypto.h>
#include <sad_hash.h>
#include <linux/if_ether.h>

#include <time.h>

#define MAX_DATA        1500

#define QUEUE_TIMEOUT   10    /* 10 seconds */

/* globals */


/* hash table for the hosts keys */

SLIST_HEAD (, keys_entry) keys_head[HASH_SIZE];

struct keys_entry {
   u_int32 ip_addr;
   DSA *key;
   SLIST_ENTRY (keys_entry) next;
};

/* a list of the per-interface Certification Authority */

SLIST_HEAD (, ca_entry) ca_head;

struct ca_entry {
   u_char *iface;
   u_int32 ip_addr;
   u_char ll_addr[LL_ADDR_LEN];
   DSA *key;
   int ca_time_delta;   /* used for time sincronization */
   SLIST_ENTRY (ca_entry) next;
};

/* the queue for messages which need a key not found in the hash table */

SLIST_HEAD (, queue_entry) queue_head;

struct queue_entry {
   u_char *data;
   time_t timestamp;    /* used for timouted entries removal */
   SLIST_ENTRY (queue_entry) next;
};


/* protos */

int get_key( u_int32 ip_addr, DSA **key);
void key_queue_add(struct fixed_ether_arp *earp);
void key_queue_scan(struct fixed_ether_arp *earp);
void key_request( u_int32 ip_addr);
int key_add( u_int32 ip_addr, DSA *key);
void ca_add(char *iface, u_int32 ip_addr, u_char *ll_addr, DSA *key);
int get_ca_key(char *iface, u_int32 *ip_addr, u_char *ll_addr, DSA **key);

void send_time_request(void);
u_int32 get_timestamp(char *iface);
void ca_set_delta(char *iface, u_int32 ca_time);

/*******************************************/

/*
 * add a CA in the per-interface list
 */

void ca_add(char *iface, u_int32 ip_addr, u_char *ll_addr, DSA *key)
{
   char *dummy_iface;
   struct ca_entry *e;
        
   if (GBL_OPTIONS->ca_mode) {
      DEBUG_MSG("ca_add : I'm the CA !");
      return;
   }

   DEBUG_MSG("ca_add 0x%08x %s on %s", ip_addr, ha_ntoa(ll_addr), iface);
 
//daveti: debug
printf("daveti: ca_add [%s] [%s] on [%s]\n",
	pa_ntoa((u_char *)&ip_addr),
	ha_ntoa(ll_addr),
	iface);
 
   /* 
    * do some sanity check on the vaule passed
    * from conf file...
    */
   
   if (belong_to_iface(ip_addr, &dummy_iface) == -ESARP_NOTFOUND)
      ERROR_MSG("ERROR LOADING CA KEY: %s doesn't belong to any iface", pa_ntoa((u_char *)&ip_addr));

   if (strcmp(iface, dummy_iface))
      ERROR_MSG("ERROR LOADING CA KEY: %s is not on %s", pa_ntoa((u_char *)&ip_addr), iface);     
 
   SAFE_FREE(dummy_iface);
   
   /*
    *  search if already inserted and replace it if so.
    */
   
   SLIST_FOREACH (e, &ca_head, next) {
      if (!strcmp(iface, e->iface)) {
         DSA_free(e->key);
         e->key = DSA_dup(key);
         e->ip_addr = ip_addr;
         memcpy(e->ll_addr, ll_addr, LL_ADDR_LEN);
         DEBUG_MSG("ca_add: replace %s", iface);
         return;
      }
   }

   /* not found... create and insert */
   
   DEBUG_MSG("ca_add: add %s", iface);
   
   e = calloc(1, sizeof(struct ca_entry));
   ON_ERROR(e, "cant allocate memory");
   
   e->key = DSA_dup(key);
   
   e->iface = strdup(iface);
   ON_ERROR(e->iface, "cant allocate memory");
   
   e->ip_addr = ip_addr;
   memcpy(e->ll_addr, ll_addr, LL_ADDR_LEN);
   
   SLIST_INSERT_HEAD (&ca_head, e, next);
   
}

/* 
 * retrive the CA key associated with that 
 * return ESARP_SUCCESS on success
 *       -ESARP_NOTFOUND on failure
 */

int get_ca_key(char *iface, u_int32 *ip_addr, u_char *ll_addr, DSA **key)
{
   struct ca_entry *e;

   DEBUG_MSG("get CA key %s", iface);

   SLIST_FOREACH (e, &ca_head, next) {
      if (!strcmp(e->iface, iface)) {
         if (key != NULL) 
            *key = DSA_dup(e->key);
         if (ip_addr != NULL) 
            *ip_addr = e->ip_addr;
         if (ll_addr != NULL)           
            memcpy(ll_addr, e->ll_addr, LL_ADDR_LEN);
         return ESARP_SUCCESS;
      }
   }
   
   if (key != NULL) *key = NULL;
   return -ESARP_NOTFOUND;
        
}

/*
 * add a key in the hash table
 *
 * return ESARP_SUCCESS on creation of a new entry
 *        ESARP_REPLACED if already there and replaced
 *       -ESARP_IGNORE if it is one of my address
 */

int key_add( u_int32 ip_addr, DSA *key)
{
   struct keys_entry *e;
   char *dummy;

   /* 
    * do some sanity check on the vaule passed
    * from conf file...
    */
   
   if (belong_to_iface(ip_addr, &dummy) == -ESARP_NOTFOUND)
      ERROR_MSG("ERROR LOADING KEY: %s doesn't belong to any iface", pa_ntoa((u_char *)&ip_addr));

   SAFE_FREE(dummy);
   
   /* search if already present and replace it if so. */
   
   SLIST_FOREACH (e, &keys_head[fnv_hash ((char *)&ip_addr, IP_ADDR_LEN) & HASH_MASK], next) {
      if ( e->ip_addr == ip_addr ) {
         DSA_free(e->key);
         e->key = DSA_dup(key);
         DEBUG_MSG("key_add: replace 0x%08x", ip_addr);
         return ESARP_REPLACED;
      }
   }

   /* not found... create and insert */
   
   DEBUG_MSG("key_add: add 0x%08x", ip_addr);
   
   e = calloc(1, sizeof(struct keys_entry));
   ON_ERROR(e, "cant allocate memory");
   
   e->key = DSA_dup(key);
   
   e->ip_addr = ip_addr;
   
   SLIST_INSERT_HEAD (&(keys_head[fnv_hash ((char *)&ip_addr, IP_ADDR_LEN) & HASH_MASK]), e, next);

   return ESARP_SUCCESS;
}

/*
 * retrive the key associated with that ip
 * return ESARP_SUCCESS on success
 *       -ESARP_NOTFOUND on failure
 */
//daveti: let's use cache
//#define NO_CACHE

int get_key( u_int32 ip_addr, DSA **key)
{
   struct keys_entry *e;

   SLIST_FOREACH (e, &keys_head[fnv_hash ((char *)&ip_addr, IP_ADDR_LEN) & HASH_MASK], next) {
      if ( e->ip_addr == ip_addr ) {
         *key = DSA_dup(e->key);
         DEBUG_MSG("get key 0x%08x : found", ip_addr);

//daveti: NOTE - the cache should only work for non-CA!
//The cache for CA should be static and always be there!

	 //WL: add this code to implement NO caching option
	 //effectively we delete the key once it is returned
	 //This way the key is only used once
	 #ifdef NO_CACHE
//daveti: This should be the reason why the key is missing...
if (GBL_OPTIONS->ca_mode)
{
	printf("daveti: CA get_key found key [0x%x] and then removed\n", ip_addr);
	DEBUG_MSG("daveti: CA get_key found key [0x%x] and then removed", ip_addr);

	 e->ip_addr = 0;
	 DSA_free(e->key);
}
	 #endif
         return ESARP_SUCCESS;
      }
   }
   DEBUG_MSG("get key 0x%08x : NOT FOUND", ip_addr);
   *key = NULL;
   return -ESARP_NOTFOUND;
        
}

/*
 * add to the keys queue the packet.
 */

void key_queue_add(struct fixed_ether_arp *earp)
{
   struct queue_entry *e;

   DEBUG_MSG("key_queue_add 0x%08x", *(u_int32 *)&earp->arp_spa);
   
   e = calloc(1, sizeof(struct queue_entry));
   ON_ERROR(e, "cant allocate memory");
   
   e->data = calloc(1, MAX_DATA);
   ON_ERROR(e->data, "cant allocate memory");
   
   memcpy(e->data, (u_char *)earp, MAX_DATA);
   
   e->timestamp = time(NULL);

   SLIST_INSERT_HEAD(&queue_head, e, next);
}

/*
 * as the key arrives, scan the queue to find
 * pending entries.
 * meanwhile deletes the timeouted entries
 */

void key_queue_scan(struct fixed_ether_arp *earp)
{
   struct queue_entry *e, *to_free = NULL;
   struct fixed_ether_arp *learp;
   int processed = 0;
   
   DEBUG_MSG("key_queue_scan 0x%08x", *(u_int32 *)&earp->arp_spa);
   
   SLIST_FOREACH(e, &queue_head, next) {
      
      learp = (struct fixed_ether_arp *)e->data;
      
      if (!memcmp(earp->arp_spa, learp->arp_spa, IP_ADDR_LEN)) {   /* found ! */
         char *iface = NULL;
              
         processed = 1;
         
         DEBUG_MSG("key_queue_scan: found !");
       
         if (belong_to_iface(*(u_int32 *)&learp->arp_spa, &iface) == -ESARP_NOTFOUND)
            break;   /* nearly impossible */
                 
         /*
          * verify the signature
          */

         if ( sarp_verify_sign(iface, (struct libnet_arp_hdr *)learp) == ESARP_SUCCESS) {
            DEBUG_MSG("key_queue_scan: signature correct !");
            
            DEBUG_MSG("key_queue_scan: add to the neighbor 0x%08x %s on %s",
                                  *(u_int32 *)&learp->arp_spa, ha_ntoa(learp->arp_sha),
                                  iface);
               
            neigh_add(learp->arp_sha, *(u_int32 *)&learp->arp_spa, iface, NUD_REACHABLE);
               
         } else {
            sad_syslog("%s replies with invalid signature !!", pa_ntoa(learp->arp_spa));        
         }
         
         SAFE_FREE(iface);
      }

      /*
       * free the element to be freed
       */
           
      SAFE_FREE(to_free);
      
      if (processed || e->timestamp < time(NULL) - QUEUE_TIMEOUT) {
         SAFE_FREE(e->data);
         SLIST_REMOVE(&queue_head, e, queue_entry, next);        
         
         /* 
          * we cant free e because is needed by SLIST_FOR_EACH.
          * so put it in a pointer then free it in the next loop
          *
          * if we are at the last loop there is a SAFE_FREE at 
          * the end this function
          */
         
         to_free = e;
         //SAFE_FREE(e);
      }
      processed = 0;
   }
   
   /* free pending pointer */
   
   SAFE_FREE(to_free);
}

/*
 * ask to the CA the key for that ip_addr
 */

void key_request( u_int32 ip_addr )
{
   u_char buf[1500];
   struct libnet_arp_hdr *arp;
   struct fixed_ether_arp *earp;
   struct sarp_auth_msg *sarp;
   char *iface = NULL;

   arp = (struct libnet_arp_hdr *)buf;
   earp = (struct fixed_ether_arp *)arp;
   sarp = (struct sarp_auth_msg *)(earp + 1);
   
   DEBUG_MSG("key_request 0x%08x", ip_addr);

   if (belong_to_iface(ip_addr, &iface) == -ESARP_NOTFOUND) {
      sad_syslog("Ooops... I'm asking for a non existent host 0x%08x", ip_addr);
      return;
   }
   
   memset(earp, 0, sizeof(struct fixed_ether_arp));
   memset(sarp, 0, sizeof(struct sarp_auth_msg));
   
   /*
    * XXX - this should support even hardware
    * different from ethernet and protocol from IP
    */
   
   arp->ar_hrd = htons(ARPHRD_ETHER);
   arp->ar_pro = htons(ETH_P_IP);
   
   arp->ar_hln = LL_ADDR_LEN;
   arp->ar_pln = IP_ADDR_LEN;
           
   /*
    * use ARPOP_SARP
    * this indicates that this is a special
    * packets only for SARP enabled hosts
    */
   
   arp->ar_op = htons(ARPOP_SARP);
  
   /*
    * add my addresses
    */
   
   memcpy(earp->arp_sha, iface_ll_addr(iface), LL_ADDR_LEN);
   
   *(u_int32 *)earp->arp_spa = iface_ip_addr(iface);
   
   /* 
    * fill the IP we are requesting for...
    * ip_addr is already in network order 
    */
   
   memcpy(earp->arp_tpa, (u_char *)&ip_addr, IP_ADDR_LEN); 
   
   /*
    * this is the ll_addr for the CA
    */

   get_ca_key(iface, NULL, earp->arp_tha, NULL);
  

   sarp->magic = htonl(SARP_MAGIC);
   sarp->type = SARPOP_KEY_REQUEST;
   sarp->siglen = 0;
   sarp->datalen = 0;
   sarp->timestamp = 0;
   
   /*
    * send the request
    */
   
   send_to_wire(iface, arp);

   SAFE_FREE(iface);
}

/*
 * request the timestamp to the CA(s),
 * set an alarm of 5 sec
 * if the CA(s) doesn't reply in time, shutdown the daemon
 */

void send_time_request(void)
{
   u_char buf[1500];
   struct libnet_arp_hdr *arp;
   struct fixed_ether_arp *earp;
   struct sarp_auth_msg *sarp;
   struct ca_entry *e;

   if(GBL_OPTIONS->ca_mode)
      return;
   
   arp = (struct libnet_arp_hdr *)buf;
   earp = (struct fixed_ether_arp *)arp;
   sarp = (struct sarp_auth_msg *)(earp + 1);
   
   DEBUG_MSG("sarp_send_time_request");
  

   memset(earp, 0, sizeof(struct fixed_ether_arp));
   memset(sarp, 0, sizeof(struct sarp_auth_msg));
   
   /*
    * XXX - this should support even hardware
    * different from ethernet and protocol from IP
    */

   arp->ar_hrd = htons(ARPHRD_ETHER);
   arp->ar_pro = htons(ETH_P_IP);

   arp->ar_hln = LL_ADDR_LEN;
   arp->ar_pln = IP_ADDR_LEN;
               
   /*
    * use ARPOP_SARP
    * this indicates that this is a special
    * packets only for SARP enabled hosts
    */
   
   arp->ar_op = htons(ARPOP_SARP);
   
   sarp->magic = htonl(SARP_MAGIC);
   sarp->type = SARPOP_TIME_REQUEST;
      
   /* 
    * scan all the ifaces
    * and send a request for each CA
    */
   
   SLIST_FOREACH (e, &ca_head, next) {
                     
      /* add my addresses */
      
      memcpy(earp->arp_sha, iface_ll_addr(e->iface), LL_ADDR_LEN);
      *(u_int32 *)&earp->arp_spa = iface_ip_addr(e->iface);
      
      /* this is the ll_addr for the CA */
 
      get_ca_key(e->iface, (u_int32 *)earp->arp_tpa, earp->arp_tha, NULL);
 
      /* send the request */
      
      send_to_wire(e->iface, arp);
   }
        
   /*
    * set the timeout,
    * if all the CA(s) don't reply in time
    * the daemon cannot start.
    * the SIGALRM is set to INGORE upon reception
    * of all the CA replies
    */
  
   alarm(5);   /* 5 seconds of timeout */
  
//daveti: debug
printf("daveti: alarm(5) from send_time_request\n");
 
}

/*
 * return the timestamp adjusted
 * with the CA's delta of the proper iface
 */

u_int32 get_timestamp(char *iface)
{
   struct ca_entry *e;
   int timestamp = time(NULL);
   
   /* 
    * if we are not the CA return timestamp
    * adjusted with the proper delta
    */
   
   if (!GBL_OPTIONS->ca_mode) {

      SLIST_FOREACH (e, &ca_head, next) {
         if(!strcmp(e->iface, iface))
            timestamp = time(NULL) + e->ca_time_delta;
      }
   }
   
   /*
    * else the timestamp is time(NULL)
    */
   
   DEBUG_MSG("sarp_get_timestamp: %s %d", iface, timestamp );
   
   return timestamp;
}

/*
 * adjust the the ca_delta for later use 
 * in sarp_get_timestamp
 */

void ca_set_delta(char *iface, u_int32 ca_time)
{
   struct ca_entry *e;
   
   /* the CA doesn't need adjustment */
   if (GBL_OPTIONS->ca_mode)
      return;
   
   SLIST_FOREACH (e, &ca_head, next) {
      if(!strcmp(e->iface, iface))
         e->ca_time_delta = ca_time - time(NULL);
   }
   
   DEBUG_MSG("sarp_set_delta: adjusting %d sec", ca_time - time(NULL) );
        
}

/* EOF */

// vim:ts=3:expandtab

