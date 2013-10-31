/*
    sarpd -- a daemon for ARP authentication

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
#include <sad_version.h>
#include <sad_parser.h>
#include <sad_signal.h>
#include <sad_capture.h>
#include <sad_conf.h>
#include <sad_neigh.h>
#include <sad_crypto.h>
#include <sad_key.h>


/* global vars */
//WL add l as global var
libnet_t *l;

/* protos */

void reload(void);
void sad_shutdown(void);

/*******************************************/

int main(int argc, char *argv[])
{
   /*
    * Alloc the global structures
    * We can access these structs via the macro in sad_globals.h
    */
        
   globals_alloc();
  
   GBL_PROGRAM = strdup(PROGRAM);
   GBL_VERSION = strdup(SAD_VERSION);
   GBL_DEBUG_FILE = calloc(1, strlen(PROGRAM) + strlen("_debug.log") + 1);
   ON_ERROR(GBL_DEBUG_FILE, "can't allocate debug filename");
   sprintf(GBL_DEBUG_FILE, "%s_debug.log", GBL_PROGRAM);
   
   DEBUG_INIT();
   DEBUG_MSG("main -- here we go !!");

   signal_handler();

   /*
    * getopt related parsing...
    */
   
   parse_options(argc, argv);
  
   fprintf (stdout, "\n\033[01m\033[1m%s %s (c) 2002 %s\033[0m\n\n", GBL_PROGRAM, GBL_VERSION, AUTHOR);

   /*
    * check if all the configuration file are in the right place
    * and if they are accessible
    */
   
   check_configuration();
   
   /*
    * fork and demonize
    */
   
   daemonize();
   
   DEBUG_MSG("daemon -- here we go !!");
   
   /*
    * initialize libpcap
    */
   
   capture_init();

   /* 
    * ready to go...
    * load all the configuration files
    */
  
   //WL initialize libnet
   char *dev;
   char errbuf[LIBNET_ERRBUF_SIZE];
//daveti: update to eth1 for our case
   //dev = "eth0";
   dev = "eth1";

   if ((l = init_packet_injection(dev,errbuf)) == NULL) {
     ERROR_MSG(errbuf);
   }
  
   load_configuration();

   /*
    * initialize crypto 
    * feed the PRNG with /dev/urandom
    * precalculate the kinv factor for DSA_sign
    */

   crypto_init();

   /* 
    * disable kernel reception of ARP packets via
    * /proc/sys/net/ipv4/sarp
    * daveti: update to /proc/sarp
    */
   neigh_disable_kernel();

   /*
    * flush the arp tables, so we can autenticate all the 
    * future connections from this host
    */
   
   neigh_flush_all_tables();
 
   /*
    * send the time syncronization request to 
    * the CA.
    * if the query timeout, shutdown the daemon
    * (there isn't a CA)
    *
    * the capture module is already initialized
    * so the reply is for sure captured
    */
   
   send_time_request();
   
   atexit(sad_shutdown);
   
   /*
    * go !
    * start capturing packets.
    * this fuction will never return until shutdown
    */
   
   capture();
  
   /* NOT REACHED */      

   return 0;
}

/*
 * actions to do on SIGUP
 */

void reload(void)
{
   load_configuration();
   crypto_init();
}


void sad_shutdown(void)
{
   sad_syslog("Secure ARP daemon has stopped to work. Enabling old style ARP.");
}


/* EOF */


// vim:ts=3:expandtab

