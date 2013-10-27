/*
    sarp -- error handling module

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

#include <stdarg.h>
#include <errno.h>

#define ERROR_MSG_LEN 200

void error_msg(char *file, char *function, int line, char *message, ...);

/*******************************************/

void error_msg(char *file, char *function, int line, char *message, ...)
{
   va_list ap;
   char errmsg[ERROR_MSG_LEN + 1];    /* should be enough */

   va_start(ap, message);
   vsnprintf(errmsg, ERROR_MSG_LEN, message, ap);
   va_end(ap);

   fprintf(stderr, "[%s:%s:%d]\n\n %s \n\n ERRNO %d | %s \n\n", file, function,
                   line, errmsg, errno, strerror(errno));
   exit(-1);
}

/* EOF */

// vim:ts=3:expandtab

