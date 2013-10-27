/*
    sarpd -- syslog handling module

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
#include <stdarg.h>
#include <syslog.h>

#define SYSLOG_MSG_LEN 500

void sad_syslog(char *message, ...);

/*******************************************/

void sad_syslog(char *message, ...)
{
   va_list ap;
   char logmsg[SYSLOG_MSG_LEN + 1];    /* should be enough */

   va_start(ap, message);
   vsnprintf(logmsg, SYSLOG_MSG_LEN, message, ap);
   va_end(ap);

/* XXX - fix this */   
   //fprintf(stderr, "SYSLOG : %s\n", logmsg);

   syslog(LOG_DAEMON | LOG_PID | LOG_NOTICE, logmsg);

}

/* EOF */

// vim:ts=3:expandtab

