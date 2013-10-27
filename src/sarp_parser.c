/*
    sarp -- parsing utilities

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


#include <sarp_main.h>

#ifdef HAVE_GETOPT_H
   #include <getopt.h>
#else
   #include <missing/getopt.h>
#endif

/* protos... */

void sarp_usage(void);
void parse_options(int argc, char **argv);

//-----------------------------------

void sarp_usage(void)
{

   fprintf (stdout, "\nUsage: %s [OPTIONS] \n", GBL_PROGRAM);

   fprintf (stdout, "\nGeneral options:\n");
   fprintf (stdout, "  -b, --bitlen <NUM>           number of bit for the key (def. 1024)\n\n");
   fprintf (stdout, "  -g, --genkey                 generate a keypair\n");
   fprintf (stdout, "  -s, --sign                   generate a signed info file\n");
   fprintf (stdout, "  -o, --outfile <FILE>         specify the output filename for keypair\n\n");
   fprintf (stdout, "  -c, --check                  check if the keypair is valid\n");
   fprintf (stdout, "  -i, --infile <FILE>          specify the input filename for keypair verification\n\n");
   fprintf (stdout, "  -v, --verbose                be verbose during operations\n\n");
   fprintf (stdout, "  -V, --version                prints the version and exit\n");
   fprintf (stdout, "  -h, --help                   this help screen\n");

   fprintf(stdout, "\n\n");

   exit (0);
}


void parse_options(int argc, char **argv)
{
   int c;

   static struct option long_options[] = {
      { "help", no_argument, NULL, 'h' },
      { "version", no_argument, NULL, 'V' },
      { "genkey", no_argument, NULL, 'g' },
      { "sign", no_argument, NULL, 's' },
      { "outfile", required_argument, NULL, 'o' },
      { "check", no_argument, NULL, 'c' },
      { "infile", required_argument, NULL, 'i' },
      { "verbose", no_argument, NULL, 'v' },
      { "bitlen", required_argument, NULL, 'b' },
      { 0 , 0 , 0 , 0}
   };

   optind = 0;

   while ((c = getopt_long (argc, argv, "hVgo:ci:vsb:", long_options, (int *)0)) != EOF) {

      switch (c) {

         case 'b':
                  GBL_OPTIONS->bitlen = atoi(optarg);
                  break;
                  
         case 'g':
                  GBL_OPTIONS->genkey = 1;
                  break;
                  
         case 's':
                  GBL_OPTIONS->sign = 1;
                  break;
                  
         case 'o':
         case 'i':
                  GBL_OPTIONS->file = strdup(optarg);
                  break;
                  
         case 'c':
                  GBL_OPTIONS->check = 1;
                  break;
                  
         case 'v':
                  GBL_OPTIONS->verbose = 1;
                  break;
                  
         case 'h':
                  sarp_usage();
                  break;

         case 'V':
                  printf("%s (Secure ARP client) %s\n", GBL_PROGRAM, GBL_VERSION);
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

