/*
    sarpd -- global var handling module

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

#define GBL_FREE(x) do{ if (x != NULL) free(x); }while(0)


/* global vars */

struct globals *gbls;

/* proto */

void globals_alloc(void);
void globals_free(void);

/*******************************************/

void globals_alloc(void)
{
   
   gbls = calloc(1, sizeof(struct globals));
   ON_ERROR(gbls, "can't allocate globals");
           
   gbls->options = calloc(1, sizeof(struct sarp_options));
   ON_ERROR(gbls->options, "can't allocate sad_options");

   gbls->env = calloc(1, sizeof(struct program_env));
   ON_ERROR(gbls->env, "can't allocate program_env");
  
   atexit(globals_free);
   
   return;
}


void globals_free(void)
{
 
        
   GBL_FREE(gbls->env->name);
   GBL_FREE(gbls->env->version);
   GBL_FREE(gbls->env);
   
   GBL_FREE(gbls->options->file);
   GBL_FREE(gbls->options);
   
   GBL_FREE(gbls);
   
   return;
}

/* EOF */

// vim:ts=3:expandtab

