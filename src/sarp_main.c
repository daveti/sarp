/*
    sarp -- the client for S-ARP manipulation

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
#include <sarp_parser.h>
#include <sarp_version.h>
#include <sarp_crypto.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>

/* protos */

void generate_keypair(void);
void verify_keypair(void);
void sign_info_file(void);

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

   /*
    * getopt related parsing...
    */
   
   parse_options(argc, argv);
 
   if (GBL_OPTIONS->bitlen == 0)
      GBL_OPTIONS->bitlen = DFL_SIG_BIT_LEN;   /* set the default value */
   
   fprintf (stdout, "\n\033[01m\033[1m%s %s (c) 2002 %s\033[0m\n\n", GBL_PROGRAM, GBL_VERSION, AUTHOR);

   if (GBL_OPTIONS->check && GBL_OPTIONS->genkey)
      EXIT_MSG("Cannot use check and genkey at the same time...");

   if (GBL_OPTIONS->check)
      verify_keypair();
   
   if (GBL_OPTIONS->genkey)
      generate_keypair();
   
   if (GBL_OPTIONS->sign)
      sign_info_file();
   
   return 0;
}



void generate_keypair(void)
{
   FILE *fd;
   char *pub, *priv;
   char *filename;

   /*
    * prepare the key pair
    */
   
   crypto_genkeypair(&pub, &priv);

   /*
    * if not specified on command line, the file
    * must be filled with default name
    */
   
   if (GBL_OPTIONS->file == NULL)
      GBL_OPTIONS->file = strdup("id_sarp");
   
   /*
    * save to the file the key pair
    */
   
   fd = fopen(GBL_OPTIONS->file, "w");
   ON_ERROR(fd, "Can't create %s", GBL_OPTIONS->file);

   fprintf(fd, "---BEGIN Secure ARP PRIVATE KEY---\n");
   fprintf(fd, "%s", priv);
   fprintf(fd, "---END Secure ARP PRIVATE KEY---");
   
   fclose(fd);
   
   chmod(GBL_OPTIONS->file, 0600);
   
   filename = calloc(1, strlen(GBL_OPTIONS->file) + 5);
   ON_ERROR(filename, "Can't allocate memory");
   
   sprintf(filename, "%s.pub", GBL_OPTIONS->file);
   
   fd = fopen(filename, "w");
   ON_ERROR(fd, "Cant create %s", filename);

   fprintf(fd, "---BEGIN Secure ARP PUBLIC KEY---\n");
   fprintf(fd, "%s", pub);
   fprintf(fd, "---END Secure ARP PUBLIC KEY---");
   
   fclose(fd);
   
   chmod(filename, 0644);

   fprintf(stdout, "\nKeypair saved to %s and %s\n\n", GBL_OPTIONS->file, filename);

   if (GBL_OPTIONS->verbose) {
      fprintf(stdout, "---BEGIN Secure ARP PRIVATE KEY---\n");
      fprintf(stdout, "%s", priv);
      fprintf(stdout, "---END Secure ARP PRIVATE KEY---\n\n");
      fprintf(stdout, "---BEGIN Secure ARP PUBLIC KEY---\n");
      fprintf(stdout, "%s", pub);
      fprintf(stdout, "---END Secure ARP PUBLIC KEY---\n\n");
   }
   
   SAFE_FREE(filename);
   SAFE_FREE(pub);
   SAFE_FREE(priv);

}


void verify_keypair(void)
{
   FILE *fd;
   char *pub, *priv, *correct;
   char *filename;
   char line[128];

   /*
    * if not specified on command line, the file
    * must be filled with default name
    */
   
   if (GBL_OPTIONS->file == NULL)
      GBL_OPTIONS->file = strdup("id_sarp");
   
   /* 
    * initialize the strings
    */
   
   pub = calloc(1, sizeof(char));
   priv = calloc(1, sizeof(char));
   
   /*
    * load the private key
    */
   
   fd = fopen(GBL_OPTIONS->file, "r");
   ON_ERROR(fd, "Can't read %s", GBL_OPTIONS->file);
   
   while(fgets(line, 128, fd)) {
      if (line[0] == '-') continue;    /* skip header and trailer */
      
      priv = realloc(priv, strlen(priv) + strlen(line) + 1);
      ON_ERROR(priv, "can't allocate memory");
      
      strcat(priv, line);
   }
   
   fclose(fd);

   /*
    * load the public key
    */

   filename = calloc(1, strlen(GBL_OPTIONS->file) + 5);
   ON_ERROR(filename, "Can't allocate memory");
   
   sprintf(filename, "%s.pub", GBL_OPTIONS->file);
  
   fd = fopen(filename, "r");
   ON_ERROR(fd, "Can't read %s", filename);

   while(fgets(line, 128, fd)) {
      if (line[0] == '-') continue;    /* skip header and trailer */
      
      pub = realloc(pub, strlen(pub) + strlen(line) + 1);
      ON_ERROR(pub, "can't allocate memory");

      strcat(pub, line);
   }
   
   fclose(fd);

   if ( crypto_validate_keypair(pub, priv, &correct) == -1 ) {
      fprintf(stderr, "\nPublic and Private keys don't match !!\n\n");
      if (GBL_OPTIONS->verbose) {
         fprintf(stdout, "The public key should be :\n\n");
         fprintf(stdout, "---BEGIN Secure ARP PUBLIC KEY---\n");
         fprintf(stdout, "%s", correct);
         fprintf(stdout, "---END Secure ARP PUBLIC KEY---\n\n");
      }
   } else
      fprintf(stdout, "\nPublic and Private keys are valid\n\n");
   
   SAFE_FREE(pub);
   SAFE_FREE(priv);
   SAFE_FREE(correct);
   SAFE_FREE(filename);

}

void sign_info_file(void)
{
   char ip[16], ll[18];
   int d;
   struct in_addr dummy;
   char *sig, *pub, *message;
   char *filename;
   FILE *fd;
   char line[128];

   if (GBL_OPTIONS->file == NULL)
      GBL_OPTIONS->file = strdup("id_sarp");
   
   /* 
    * initialize the strings
    */
   
   pub = calloc(1, sizeof(char));
   
   filename = calloc(1, strlen(GBL_OPTIONS->file) + 10);
   ON_ERROR(filename, "Can't allocate memory");
   
   sprintf(filename, "%s.pub", GBL_OPTIONS->file);
   
   /*
    * load the public key file
    */
   
   fd = fopen(filename, "r");
   ON_ERROR(fd, "Can't read %s", filename);
   
   while(fgets(line, 128, fd)) {
      if (line[0] == '-') continue;    /* skip header and trailer */
      
      pub = realloc(pub, strlen(pub) + strlen(line) + 1);
      ON_ERROR(pub, "can't allocate memory");
      
      strcat(pub, line);
   }
   
   fclose(fd);
   
   fprintf(stdout, "Insert the IP: ");
   fflush(stdout);
   scanf("%16s", ip);
   fprintf(stdout, "\n");
  
   if (sscanf(ip, "%d.%d.%d.%d", &d, &d, &d, &d) != 4)
      EXIT_MSG("Invalid IP address");
   
   if ( inet_aton(ip, &dummy) == 0)
      EXIT_MSG("Invalid IP address");
  
   fprintf(stdout, "Informaton below is needed only for the CA.\n");
   fprintf(stdout, "Enter '0' for commnon hosts...\n\n");
   fprintf(stdout, "Insert the Link Layer Address : ");
   fflush(stdout);
   scanf("%17s", ll);
   fprintf(stdout, "\n");

   if (!strcmp(ll, "0")) 
      strcpy(ll, "00:00:00:00:00:00");
   
   if (sscanf(ll, "%02X:%02X:%02X:%02X:%02X:%02X", &d, &d, &d, &d, &d, &d) != 6)
      EXIT_MSG("Invalid Link Layer Address");
   
   message = calloc(1, strlen(ip) + strlen(ll) + strlen(pub) + 128);
   ON_ERROR(message, "Can't allocate memory");

   sprintf(message, SARP_FILE_FORMAT_STRING, 
                    ip, 
                    ll, 
                    pub);
  
   
   crypto_sign_info(message, &sig); 
  
   sprintf(filename, "%s.sarp", GBL_OPTIONS->file);
   
   fd = fopen(filename, "w");
   ON_ERROR(fd, "Can't create %s file", filename);

   fprintf(fd, "%s", message);
   fprintf(fd, "%s", sig);
   
   fclose(fd);
   
   chmod(filename, 0644);
   
   fprintf(stdout, "\nInfo file saved to %s\n\n", filename);
   
   SAFE_FREE(pub);
   SAFE_FREE(sig);
   SAFE_FREE(filename);
   SAFE_FREE(message);
}


/* EOF */

// vim:ts=3:expandtab

