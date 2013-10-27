/*
    sarpd -- parsing utilities

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

#ifdef HAVE_GETOPT_H
   #include <getopt.h>
#else
   #include <missing/getopt.h>
#endif

/* protos... */

void sad_usage(void);
void parse_options(int argc, char **argv);

//-----------------------------------

void sad_usage(void)
{

   DEBUG_MSG("sad_usage");

   fprintf (stdout, "\nUsage: %s [OPTIONS] \n", GBL_PROGRAM);

   fprintf (stdout, "\nGeneral options:\n");
   fprintf (stdout, "  -A, --akd-mode               use this daemon as the AKD\n\n");
   fprintf (stdout, "  -p, --prefix <PATH>          use this prefix to find config files\n");
   fprintf (stdout, "  -c, --conf <FILE>            load configuration from this file\n");
   fprintf (stdout, "  -k, --known_hosts <FILE>     load known_hosts from this file\n\n");
   fprintf (stdout, "  -v, --version                prints the version and exit\n");
   fprintf (stdout, "  -h, --help                   this help screen\n");

   fprintf(stdout, "\n\n");

   exit (0);
}


void parse_options(int argc, char **argv)
{
   int c;

   static struct option long_options[] = {
      { "help", no_argument, NULL, 'h' },
      { "version", no_argument, NULL, 'v' },
      { "conf", required_argument, NULL, 'c' },
      { "known_hosts", required_argument, NULL, 'k' },
      { "prefix", required_argument, NULL, 'p' },
      { "akd-mode", no_argument, NULL, 'A' },
      { 0 , 0 , 0 , 0}
   };

   for (c = 0; c < argc; c++)
      DEBUG_MSG("parse_options -- [%d] [%s]", c, argv[c]);

   optind = 0;

   while ((c = getopt_long (argc, argv, "hv:c:k:p:A", long_options, (int *)0)) != EOF) {

      switch (c) {

         case 'c':
                  GBL_OPTIONS->conf_file = strdup(optarg);
                  break;
                  
         case 'k':
                  GBL_OPTIONS->known_file = strdup(optarg);
                  break;
                  
         case 'p':
                  GBL_PREFIX = strdup(optarg);
                  break;
                  
         case 'A':
                  GBL_OPTIONS->ca_mode = 1;
                  break;
                  
         case 'h':
                  sad_usage();
                  break;

         case 'v':
                  printf("%s (Secure ARP daemon) %s\n", GBL_PROGRAM, GBL_VERSION);
                  exit(0);
                  break;

         case ':': // missing parameter
            fprintf(stdout, "\nTry `%s --help' for more options.\n\n", GBL_PROGRAM);
            exit(0);
         break;

         case '?': // unknown option
            fprintf(stdout, "\nTry `%s --help' for more options.\n\n", GBL_PROGRAM);
            exit(0);
         break;
      }
   }

   return;
}


/* EOF */


// vim:ts=3:expandtab

