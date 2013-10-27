/*
    sarpd -- debug module

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

#ifdef DEBUG

#include <stdarg.h>
#ifdef HAVE_SYS_UTSNAME_H
   #include <sys/utsname.h>
   #include <features.h>
#endif

#include <sad_debug_info.h>

/* globals */

FILE *debug_file;

/* protos */

void debug_init(void);
void debug_close(void);
void debug_msg(char *message, ...);

char * hex_format(const u_char *buffer, int buff_len);

/**********************************/

void debug_init(void)
{
#ifdef HAVE_SYS_UTSNAME_H
   struct utsname buf;
#endif

   if ((debug_file = fopen (GBL_DEBUG_FILE, "w")) == NULL) {
      ERROR_MSG("Couldn't open for writing %s", GBL_DEBUG_FILE);
   }
   
   fprintf (debug_file, "\n==============================================================\n\n");
   fprintf (debug_file, "Configured with  :  %s \n\n", configure_line);
   fprintf (debug_file, "Detected options :  DEBUG  %s \n", configure_debug);
   fprintf (debug_file, "\n==============================================================\n");
                   
  	fprintf (debug_file, "\n-> %s %s\n\n", GBL_PROGRAM, GBL_VERSION);
   #ifdef HAVE_SYS_UTSNAME_H
      uname(&buf);
      fprintf (debug_file, "-> running on %s %s %s\n", buf.sysname, buf.release, buf.machine);
   #endif
   #if defined (__GLIBC__) && defined (__GLIBC_MINOR__)
      fprintf (debug_file, "-> glibc version %d.%d\n", __GLIBC__, __GLIBC_MINOR__);
   #endif
   #if defined (__GNUC__) && defined (__GNUC_MINOR__)
      fprintf (debug_file, "-> compiled with gcc %d.%d\n", __GNUC__, __GNUC_MINOR__);
   #endif
   fprintf (debug_file, "\n\nDEVICE OPENED FOR %s DEBUGGING\n\n", GBL_PROGRAM);
   fflush(debug_file);
   atexit(debug_close);
}



void debug_close(void)
{
   fclose (debug_file);
}



void debug_msg(char *message, ...)
{
   va_list ap;
   char debug_message[strlen(message)+2];

   fprintf (debug_file, "[%5d]\t", getpid());

   strlcpy(debug_message, message, sizeof(debug_message));
   strlcat(debug_message, "\n", sizeof(debug_message));

   va_start(ap, message);
   vfprintf(debug_file, debug_message, ap);
   va_end(ap);

#if 0
/* XXX - removeme */
   va_start(ap, message);
   vprintf(debug_message, ap);
   va_end(ap);
/******************/
#endif 
   
   fflush(debug_file);
}


/* 
 * printf a binary string in a 
 * readable form
 */

char * hex_format(const u_char *buffer, int buff_len)
{
   static char *hexdata = NULL;
   int i, j, jm;
   int c, dim = 0;
   int cr = 16;

   if (buff_len == 0) return "";

   c = cr*4 + 11;
   dim = c;

   for (i = 0; i < buff_len; i++)   // approximately
      if ( i % cr == 0)             // approximately
         dim += c;                  // approximately


   SAFE_FREE(hexdata);
   
   if ( (hexdata = (char *)calloc(dim, sizeof(char))) == NULL)
      ERROR_MSG("calloc()");

   sprintf(hexdata,"\n");
   for (i = 0; i < buff_len; i += cr) {
           sprintf(hexdata, "%s %04x: ", hexdata, i );
           jm = buff_len - i;
           jm = jm > cr ? cr : jm;

           for (j = 0; j < jm; j++) {
                   if ((j % 2) == 1) sprintf(hexdata, "%s%02x ", hexdata, (unsigned char) buffer[i+j]);
                   else sprintf(hexdata, "%s%02x", hexdata, (unsigned char) buffer[i+j]);
           }
           for (; j < cr; j++) {
                   if ((j % 2) == 1) strcat(hexdata, "   ");
                   else strcat(hexdata, "  ");
           }
           strcat(hexdata, " ");

           for (j = 0; j < jm; j++) {
                   c = buffer[i+j];
                   c = isprint(c) ? c : '.';
                   sprintf(hexdata, "%s%c", hexdata, c);
           }
           strcat(hexdata,"\n");
   }

   return hexdata;
}

#endif /* DEBUG */

/* EOF */

// vim:ts=3:expandtab

