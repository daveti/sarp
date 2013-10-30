/*
    sarp -- LKM for Secure ARP authentication

    Copyright (C) 2002  ALoR <alor@users.sourceforge.net>

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

   history:

   0.9 - ported to kernel 2.2.x (thanks to gigi sullivan)
   0.8 - added CONFIG_MODVERSIONS (thanks to gigi sullivan)
   0.7 - arp_packet_type address is from System.map (passed by Makefile)
   0.5 - disable secure arp on exit
   0.3 - moved in /proc/sys/net/ipv4/sarp
   0.1 - inizial version - extracted fro kernel patch
   
   0.X - make it work on kernel 3.2.0
	 Oct 29, 2013
	 daveti@cs.uoregon.edu
	 http://davejingtian.org
 
*/

#define __KERNEL__
#define MODULE

//daveti: kernel version checking for autoconf.h
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
#include <linux/autoconf.h>
#else
#include <generated/autoconf.h>
#endif
//#include <linux/autoconf.h>
#ifdef CONFIG_MODVERSIONS
#include <linux/modversions.h>
#endif
#include <linux/config.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/version.h>
#include <asm/uaccess.h>

#include <linux/netdevice.h>  /* dev_[add|remove]_pack */
#include <net/arp.h>          /* arp_recv */


#define MODULE_NAME    "sarp"
#define MODULE_VERSION "0.9"
//daveti
#define SARP_PROC_PATH "/proc/sarp"

MODULE_AUTHOR("Alberto Ornaghi");
MODULE_DESCRIPTION("Secure ARP");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
MODULE_LICENSE("GPL");
#endif

/* 
 * this structure is declared in net/ipv4/arp.c 
 * we need its address.
 * so Makefile greps the /boot/System.map searching for it
 * then it pass the value in the ARP_PACKET_TYPE_ADDR
 */

struct packet_type *arp_packet_type = (void *)ARP_PACKET_TYPE_ADDR;

#if 0
static struct packet_type arp_packet_type = {
   type: __constant_htons(ETH_P_ARP),
   func: arp_rcv,
   data: (void*) 1, /* understand shared skbs */
};
#endif

/* globals */

int secure_arp_enabled = 0;

/* protos */

int secure_arp_proc_read (char *buf, char **start, off_t offs, int len);
ssize_t secure_arp_proc_write( struct file *file, const char *buf, size_t length, loff_t *offset);
void enable_sarp(void);
void disable_sarp(void);


/*************************************/

void enable_sarp(void)
{
   secure_arp_enabled = 1;
   
   dev_remove_pack(arp_packet_type);
   
   printk(KERN_INFO "[secure_arp] enabled\n");
   printk(KERN_INFO "[secure_arp] kernel can now reveive ARP entries "\
                          "only through SARP daemon\n");
}


void disable_sarp(void)
{
   secure_arp_enabled = 0;
         
   dev_add_pack(arp_packet_type);
         
   printk(KERN_INFO "[secure_arp] disabled\n");
   printk(KERN_INFO "[secure_arp] kernel can now receive \"classic\" "\
                          "ARP packets\n");
}


int secure_arp_proc_read (char *buf, char **start, off_t offs, int len) 
{  
   int written;
   
   MOD_INC_USE_COUNT;
   
   written = sprintf(buf, "%d\n", secure_arp_enabled);

   MOD_DEC_USE_COUNT;
   
   return written;
}

ssize_t secure_arp_proc_write( struct file *file, const char *buf, size_t length, loff_t *offset)
{
   #define MESSAGE_LEN 5
   int i, value;
   char *message;

   MOD_INC_USE_COUNT;

   message = kmalloc(MESSAGE_LEN, GFP_KERNEL);

   for (i = 0; i < MESSAGE_LEN-1 && i < length; i++)
      get_user(message[i], buf + i);
   
   message[i]='\0';
   value = simple_strtoul(message, NULL, 10);
   kfree(message);
 
   switch(value) {
      case 1:   /* enable it */
         if (secure_arp_enabled) {
            MOD_DEC_USE_COUNT;
            return i;
         }
         
         enable_sarp();      
         
         break;
      case 0:   /* disable it */
         if (!secure_arp_enabled) {
            MOD_DEC_USE_COUNT;
            return i;
         }
   
         disable_sarp();
         
         break;
      default:  /* error */
         MOD_DEC_USE_COUNT;
         return -1;
         break;
   }
  
   MOD_DEC_USE_COUNT;
  
   return i;                                                
}

/*
 * init and exit functions
 */


static int __init sarp_init(void)
{
   struct proc_dir_entry *sarp_entry;
  
//daveti: update the proc entry 
   //sarp_entry = create_proc_entry("sys/net/ipv4/sarp", 0644, NULL);
   sarp_entry = create_proc_entry(SARP_PROC_PATH, 0644, NULL);
   
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
   sarp_entry->owner = THIS_MODULE;
#endif
   sarp_entry->read_proc = (read_proc_t *)&secure_arp_proc_read;
   sarp_entry->write_proc = (write_proc_t *)&secure_arp_proc_write;
   
   printk(KERN_INFO "%s %s module loaded\n", MODULE_NAME, MODULE_VERSION);
   return 0;
}


static void __exit sarp_exit(void)
{
//daveti: update proc entry
   //remove_proc_entry("sys/net/ipv4/sarp", NULL);
   remove_proc_entry(SARP_PROC_PATH, NULL);

   if (secure_arp_enabled)
      disable_sarp();
   
   printk(KERN_INFO "%s %s removed\n", MODULE_NAME, MODULE_VERSION);
}


EXPORT_NO_SYMBOLS;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
module_init(sarp_init);
module_exit(sarp_exit);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0)
void cleanup_module(void)
{
   sarp_exit();
}

int init_module(void)
{
   return sarp_init();
}
#endif

/* EOF */

// vim:ts=3:expandtab

