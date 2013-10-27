/*
    sarpd -- configuration file handling module

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
#include <sad_hash.h>
#include <sad_inet.h>
#include <sad_crypto.h>
#include <sad_key.h>

#include <libnet.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>


#define LOAD_ENTRY(p,h,v)  do{               \
   (p) = malloc (sizeof (struct kh_entry));  \
   if ((p) == NULL )                         \
      ERROR_MSG("malloc()");                 \
   memcpy((p)->ll_addr, ha_aton(h), LL_ADDR_LEN);   \
   (p)->ip = inet_addr(v);                   \
}while(0)


SLIST_HEAD (, kh_entry) kh_head[HASH_SIZE];

struct kh_entry {
   u_char ll_addr[LL_ADDR_LEN];
   u_int32 ip;
   SLIST_ENTRY (kh_entry) entries;
};

#define DEFAULT_CONF_FILE  "/etc/sarpd/sarpd_conf"
#define DEFAULT_KNOWN_FILE "/etc/sarpd/known_hosts"

/* protos */

void check_configuration(void);
void load_configuration(void);

void load_known_hosts(void);
void load_conf(void);
void ca_load_keys(char *param);

void free_known_hosts(void);
int search_known_hosts(char *ll_addr, u_int32 ip);

/*******************************************/

void check_configuration(void)
{
   int fd;

   DEBUG_MSG("check_configuration");
   
   /* check if the LKM was loaded */
#if 0   
   if ((fd = open("/proc/sys/net/ipv4/sarp", O_RDONLY)) == -1)
      ERROR_MSG("can't access /proc/sys/net/ipv4/sarp");
   else
      close(fd);
#endif
   
   /* 
    * fill the structures if the users didn't specified them on command line 
    * in that case the pointers are NULL because getopts parsing didn't
    * filled them.
    */

   if (GBL_OPTIONS->conf_file == NULL)
      GBL_OPTIONS->conf_file = strdup(DEFAULT_CONF_FILE);

   if (GBL_OPTIONS->known_file == NULL)
      GBL_OPTIONS->known_file = strdup(DEFAULT_KNOWN_FILE);
   
   /*
    * check if prefix was specified on command line
    * and add it before all the conf file
    */

   if (GBL_PREFIX) {
      int prefix_len = strlen(GBL_PREFIX);
      int len;
      
      len = strlen(GBL_OPTIONS->conf_file);
      GBL_OPTIONS->conf_file = realloc(GBL_OPTIONS->conf_file, len + prefix_len + 1);
      memmove(GBL_OPTIONS->conf_file + prefix_len, GBL_OPTIONS->conf_file, len);
      GBL_OPTIONS->conf_file[prefix_len + len] = 0;
      memcpy(GBL_OPTIONS->conf_file, GBL_PREFIX, prefix_len);

      len = strlen(GBL_OPTIONS->known_file);
      GBL_OPTIONS->known_file = realloc(GBL_OPTIONS->known_file, len + prefix_len + 1);
      memmove(GBL_OPTIONS->known_file + prefix_len, GBL_OPTIONS->known_file, len);
      GBL_OPTIONS->known_file[prefix_len + len] = 0;
      memcpy(GBL_OPTIONS->known_file, GBL_PREFIX, prefix_len);
   }
   
   /* 
    * check for compatibility file in which are stored the
    * hosts that doesn't support SARP, but we want to connect to
    */
   
   if ((fd = open(GBL_OPTIONS->known_file, O_RDONLY)) == -1)
      ERROR_MSG("can't access known_hosts file : %s", GBL_OPTIONS->known_file);
   else
      close(fd);
   
   /* configuration file */
   
   if ((fd = open(GBL_OPTIONS->conf_file, O_RDONLY)) == -1)
      ERROR_MSG("can't access conf file : %s", GBL_OPTIONS->conf_file);
   else
      close(fd);
   
}

void load_configuration(void)
{

   DEBUG_MSG("load_configuration");
   
   load_known_hosts();
   load_conf();
        
}


void load_known_hosts(void)
{
   struct kh_entry *p;

   char line[80];
   char ip[IP_ASCII_ADDR_LEN + 1];
   char ll_addr[LL_ASCII_ADDR_LEN + 1];
   
   FILE *f;

   /*
    * flush the existing hash table.
    * so we can reload known_host with this function
    */
   
   DEBUG_MSG("flushing old known hosts");
   
   free_known_hosts();

   DEBUG_MSG("loading new known hosts from %s", GBL_OPTIONS->known_file);
   
   f = fopen (GBL_OPTIONS->known_file, "r");
   ON_ERROR(f, "cant open %s", GBL_OPTIONS->known_file);

   while (fgets (line, 80, f) != 0) {

      if (sscanf (line, "%17s %16[^,\n],\n", ll_addr, ip) != 2)
         continue;
      
      /* skip comment */
      if (ll_addr[0] == '#')
         continue;
    
      LOAD_ENTRY (p, ll_addr, ip);

      SLIST_INSERT_HEAD (&(kh_head[fnv_hash (ha_aton(ll_addr), LL_ADDR_LEN) & HASH_MASK]), p, entries);
   }

   fclose(f);

   atexit(free_known_hosts);
}



void free_known_hosts(void)
{
   struct kh_entry *l;
   int i;

   for (i = 0; i < HASH_SIZE; i++) {

	   while (SLIST_FIRST (&kh_head[i]) != NULL) {
	      l = SLIST_FIRST (&kh_head[i]);
	      SLIST_REMOVE_HEAD (&kh_head[i], entries);
	      free(l);
	   }
   }

   return;
}

/*
 * search the hash table for the requested link layer address
 * return: ESARP_SUCCESS on success
 *         -ESARP_NOTFOUND on failure
 */

int search_known_hosts(char *ll_addr, u_int32 ip)
{
   struct kh_entry *l;

   DEBUG_MSG("search_known_hosts %s 0x%08x", ha_ntoa(ll_addr), ip);
   
   SLIST_FOREACH (l, &kh_head[fnv_hash (ll_addr, LL_ADDR_LEN) & HASH_MASK], entries) {
      if (!memcmp(l->ll_addr, ll_addr, LL_ADDR_LEN) && ip == l->ip)
         return ESARP_SUCCESS;
   }

   return -ESARP_NOTFOUND;
}


void load_conf(void)
{
   FILE *fd;
   char line[128];
   char key[10], subkey[10], param[64];
   char *file;

   DEBUG_MSG("load_conf %s", GBL_OPTIONS->conf_file);
   
   fd = fopen(GBL_OPTIONS->conf_file, "r");
   ON_ERROR(fd, "Can't open conf file : %s", GBL_OPTIONS->conf_file);
   
   while (fgets (line, 128, fd) != 0) {

      /* skip comment and void lines */
      if (line[0] == '#' || line[0] == ' ')
         continue;

      memset(key, 0, sizeof(key));
      memset(subkey, 0, sizeof(subkey));
      memset(param, 0, sizeof(param));
      
      /*
       * match string in the form:
       * alpha[beta]: gamma
       * and split it in three strings.
       */
     
      if (sscanf (line, "%10[^[][%10[^]]]: %64[^,\n],\n", key, subkey, param) != 3)
         continue;
     
   
      if (GBL_PREFIX) {
         file = calloc(1, strlen(GBL_PREFIX) + strlen(param) + 1);
         ON_ERROR(file, "Can't allocate memory");

         sprintf(file, "%s%s", GBL_PREFIX, param);
      } else {
         file = strdup(param);
      }
     
      DEBUG_MSG("%s -- %s", key, file);
      
      if (!strcmp(key, "CAKey")) {
         u_int32 ip_addr;
         u_char ll_addr[LL_ADDR_LEN];
         DSA *dsa;
         
         crypto_load_sarp_file(file, &ip_addr, ll_addr, &dsa);

         /* 
          * add the CA key in the key list, since
          * even the CA is a host in the lan
          */
         
         key_add(ip_addr, dsa);
         
         /*
          * add the CA to the per-interface CA list
          */
         
         ca_add(subkey, ip_addr, ll_addr, dsa);
         
         DSA_free(dsa);
      }
                      
      if (!strcmp(key, "MYKey"))
         crypto_load_file(file, LOAD_PRIV, (DSA **)&GBL_CRYPTO_KEY);
                      
      if (!strcmp(key, "DHCPKey"))
         DEBUG_MSG("DHCP support not yet implemented");
      
      if (!strcmp(key, "KEYDir") && GBL_OPTIONS->ca_mode) 
         ca_load_keys(file);
      
      
      SAFE_FREE(file);
   }

   fclose(fd);
}

/*
 * load all the hosts key for the dir 
 * specified in the conf file
 *
 * this operation is done only by the CA
 */

void ca_load_keys(char *param)
{
   struct dirent **namelist;
   int n, i, hosts = 0;
   DSA *dsa;
   u_int32 ip_addr;
   u_char ll_addr[LL_ADDR_LEN];
   char file[256];

   DEBUG_MSG("ca_load_keys from : %s", param);

   if ( (n = scandir(param, &namelist, 0, alphasort)) == -1)
      ERROR_MSG("%s does not exist !!", param);
      
   
   for( i = 0; i < n; i++) {
      
      if (!strcmp(namelist[i]->d_name, ".") ||
          !strcmp(namelist[i]->d_name, ".."))
         continue;

      
      /*
       * prepare the complete filename
       */
      
      snprintf(file, 255, "%s/%s", param, namelist[i]->d_name);
      
      DEBUG_MSG("ca_load_keys: %s", file);
      
      /* load the certificate */
      
      crypto_load_sarp_file(file, &ip_addr, ll_addr, &dsa);

      /* add the key */

      if ( key_add(ip_addr, dsa) == ESARP_SUCCESS)
         /* increment the number of loaded hosts */
         hosts++;
     
      /* clear the whole thing */
      
      ip_addr = 0;
      memset(ll_addr, 0, LL_ADDR_LEN);
      DSA_free(dsa);
      SAFE_FREE(namelist[i]);
   }
   
   sad_syslog("CA: %d host key loaded", hosts);
  
   SAFE_FREE(namelist);
}


/* EOF */

// vim:ts=3:expandtab

