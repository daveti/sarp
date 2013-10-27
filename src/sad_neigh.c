/*
    sarpd -- neighbor (arp tables in kernel space) handling module

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
#include <sad_inet.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#include <libnetlink.h>
#include <utils.h>

#include <pcap.h>

static struct {
	int family;
   int index;
	int state;
	int unused_only;
	inet_prefix pfx;
	int flushed;
	char *flushb;
	int flushp;
	int flushe;
	struct rtnl_handle *rth;
} filter;

/* to fix a linking problem with utils */
int resolve_hosts = 0;

void neigh_disable_kernel(void);
void neigh_enable_kernel(void);

void neigh_flush_table(char *iface);
void neigh_flush_all_tables(void);
void neigh_add(char *ll_addr, u_int32 ip, char *iface, int nud);
void neigh_remove(char *ll_addr, u_int32 ip, char *iface);

int ipneigh_modify(int cmd, int flags, int nud, char *ll_addr, u_int32 ip, char *iface);
int count_neigh(struct sockaddr_nl *who, struct nlmsghdr *n, void *arg);

/*******************************************/

/*
 * activate the kernel space functions
 */

void neigh_disable_kernel(void)
{
   int fd;

   DEBUG_MSG("neigh_disable_kernel");
   
   if ((fd = open("/proc/sys/net/ipv4/sarp", O_WRONLY)) == -1)
      ERROR_MSG("can't open /proc/sys/net/ipv4/sarp");

   if (write(fd, "1", 1) != 1)
      ERROR_MSG("can't enable secure arp");

   close(fd);

   atexit(neigh_enable_kernel);
}

/*
 * disable the kernel functions
 * (called at exit)
 */

void neigh_enable_kernel(void)
{
   int fd;

   DEBUG_MSG("neigh_enable_kernel");
   
   if ((fd = open("/proc/sys/net/ipv4/sarp", O_WRONLY)) == -1)
      ERROR_MSG("can't open /proc/sys/net/ipv4/sarp");

   if (write(fd, "0", 1) != 1)
      ERROR_MSG("can't disable secure arp");

   close(fd);
}

/*
 * flush the neigh tables of all ifaces
 */

void neigh_flush_all_tables(void)
{
   pcap_if_t *curdev, *nextdev;

   DEBUG_MSG("neigh_flush_all_tables");
   
   for (curdev = (pcap_if_t *)GBL_PCAP->ifs; curdev != NULL; curdev = nextdev) {
      nextdev = curdev->next;

      neigh_flush_table(curdev->name);
   }
}

/*
 * delete all the entries in the neighbor table
 * delete all but permanent entries
 */

void neigh_flush_table(char *iface)
{
	struct rtnl_handle rth;
	char flushb[4096-512];

   DEBUG_MSG("neigh_flush_table %s", iface);
   
	memset(&filter, 0, sizeof(filter));

   filter.state = ~0;
   filter.family = AF_INET;

   /* flush all but permanent and noarp */
    
	filter.state = ~(NUD_PERMANENT|NUD_NOARP);

   /* open the netlink socket */
   
	if (rtnl_open(&rth, 0) < 0)
		ERROR_MSG("rtnl_open()");

	ll_init_map(&rth);

   /* fill the device data */
   
   if ((filter.index = ll_name_to_index(iface)) == 0)
      ERROR_MSG("ll_name_to_index(%s)", iface);


	filter.flushb = flushb;
	filter.flushp = 0;
	filter.flushe = sizeof(flushb);
	filter.rth = &rth;
	filter.state &= ~NUD_FAILED;

	for (;;) {
		if (rtnl_wilddump_request(&rth, filter.family, RTM_GETNEIGH) < 0) 
         ERROR_MSG("rtnl_wilddump_request()");
      
		filter.flushed = 0;
		
      /* 
       * count how many neigh are to be flushed 
       * and prepare the data
       */
      
      if (rtnl_dump_filter(&rth, count_neigh, stdout, NULL, NULL) < 0) 
         ERROR_MSG("rtnl_dump_filter()");
      
		if (filter.flushed == 0)
         return;
		
		if (rtnl_send(filter.rth, filter.flushb, filter.flushp) < 0)
			ERROR_MSG("rtnl_send()");
      
      filter.flushp = 0;
 
      DEBUG_MSG("*** deleting %d entries ***", filter.flushed);
	}
}

/*
 * add an entry in the neighbor table.
 * if it already exist, replace it.
 * ll_addr and ip must be in network order
 */

void neigh_add(char *ll_addr, u_int32 ip, char *iface, int nud)
{
   DEBUG_MSG("neigh add %s %s %s", ha_ntoa(ll_addr), inet_ntoa(*(struct in_addr *)&ip),
                   iface);
   
   ipneigh_modify(RTM_NEWNEIGH, NLM_F_CREATE|NLM_F_REPLACE, nud, 
                   ll_addr, ip, iface);
}

/*
 * remove an entry from the table
 * ll_addr and ip must be in network order
 */

void neigh_remove(char *ll_addr, u_int32 ip, char *iface)
{
   DEBUG_MSG("neigh remove %s %s %s", ha_ntoa(ll_addr), 
                   inet_ntoa(*(struct in_addr *)&ip), iface);
   
   ipneigh_modify(RTM_DELNEIGH, 0, 0, ll_addr, ip, iface);
}


/*
 * netlink manipulation
 */

int ipneigh_modify(int cmd, int flags, int nud, char *ll_addr, u_int32 ip, char *iface)
{
	struct rtnl_handle rth;
	struct {
		struct nlmsghdr 	n;
		struct ndmsg 		ndm;
		char   			   buf[256];
	} req;
   
	inet_prefix dst;

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | flags;
	req.n.nlmsg_type = cmd;
	req.ndm.ndm_family = AF_INET;
	
   /* 
    * the state of the entries 
    * SARP messages can nevere expire since they are 
    * authenticated. they will be replaced if a new
    * SARP message is received
    */
   
   req.ndm.ndm_state = nud;

   /* add the IP */
   
   get_addr(&dst, inet_ntoa(*(struct in_addr *)&ip), AF_INET);
	addattr_l(&req.n, sizeof(req), NDA_DST, &dst.data, dst.bytelen);

   /* add the link layer address */
   
	addattr_l(&req.n, sizeof(req), NDA_LLADDR, ll_addr, LL_ADDR_LEN);

   /* open the netlink socket */
   
	if (rtnl_open(&rth, 0) < 0)
		ERROR_MSG("rtnl_open()");

	ll_init_map(&rth);

   /* find the iface index */
   
	if ((req.ndm.ndm_ifindex = ll_name_to_index(iface)) == 0) 
      ERROR_MSG("ll_name_to_index()");

   /* send data */
   
	if (rtnl_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL) < 0)
		ERROR_MSG("rtnl_talk()");
 
   return 0;
}




int count_neigh(struct sockaddr_nl *who, struct nlmsghdr *n, void *arg)
{
	struct ndmsg *r = NLMSG_DATA(n);

	if (filter.flushb && n->nlmsg_type != RTM_NEWNEIGH)
		return 0;

	if (filter.family && filter.family != r->ndm_family)
		return 0;
   
	if (filter.index && filter.index != r->ndm_ifindex)
		return 0;
	
   if (!(filter.state & r->ndm_state) &&
	    (r->ndm_state || !(filter.state & 0x100)) &&
             (r->ndm_family != AF_DECnet))
		return 0;
   
	if (filter.flushb) {
		struct nlmsghdr *fn;
		if (NLMSG_ALIGN(filter.flushp) + n->nlmsg_len > filter.flushe) {
		   if (rtnl_send(filter.rth, filter.flushb, filter.flushp) < 0)
            return -1;
      
         filter.flushp = 0;
		}
		fn = (struct nlmsghdr*)(filter.flushb + NLMSG_ALIGN(filter.flushp));
		memcpy(fn, n, n->nlmsg_len);
		fn->nlmsg_type = RTM_DELNEIGH;
		fn->nlmsg_flags = NLM_F_REQUEST;
		fn->nlmsg_seq = ++filter.rth->seq;
		filter.flushp = (((char*)fn) + n->nlmsg_len) - filter.flushb;
		filter.flushed++;
		
	}

	return 0;
}

/* EOF */

// vim:ts=3:expandtab

