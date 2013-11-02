/*
    sarpd -- signal handler

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
#include <sad_neigh.h>

#include <signal.h>
#include <sys/resource.h>

void signal_handler(void);
void daemonize(void);

RETSIGTYPE signal_SEGV(int sig);
RETSIGTYPE signal_TERM(int sig);
RETSIGTYPE signal_HUP(int sig);
RETSIGTYPE signal_ALRM(int sig);


/*************************************/

void signal_handler(void)
{
   DEBUG_MSG("signal_handler activated");

   signal(SIGSEGV,  signal_SEGV);
   signal(SIGINT,   signal_TERM);
   signal(SIGHUP,   signal_HUP);
   signal(SIGTERM,  signal_TERM);
   signal(SIGCHLD,  SIG_IGN);       /* if I kill a forked process it doesn't become a zombie... */
   signal(SIGPIPE,  signal_TERM);
   signal(SIGALRM,  signal_ALRM);
}


RETSIGTYPE signal_SEGV(int sig)
{
//daveti: debug
printf("daveti: into signal_SEGV()\n");

#ifdef DEBUG

   struct rlimit corelimit = {RLIM_INFINITY, RLIM_INFINITY};

   DEBUG_MSG("Segmentation Fault...");
   
   fprintf (stderr, "\n\033[01m\033[1m Ooops !! This shouldn't happen...\n\n");
   fprintf (stderr, "Segmentation Fault...\033[0m\n\n");

   fprintf (stderr, "===========================================================================\n");
   fprintf (stderr, " To report this error follow these steps:\n\n");
   fprintf (stderr, "  1) recompile %s in debug mode : \n"
                    "  \t\"configure --enable-debug && make clean && make\"\n\n", GBL_PROGRAM);
   fprintf (stderr, "  2) reproduce the critical situation\n\n");
   fprintf (stderr, "  3) make a report : \"tar zcvf error.tar.gz %s_debug.log \"\n\n", GBL_PROGRAM);
   fprintf (stderr, "  4) get the gdb backtrace :\n"
                    "  \t - \"gdb %s core\"\n"
                    "  \t - at the gdb prompt \"bt\"\n"
                    "  \t - at the gdb prompt \"quit\" and return to the shell\n"
                    "  \t - copy and paste this output.\n\n", GBL_PROGRAM);
   fprintf (stderr, "  5) mail me the output of gdb and the error.tar.gz\n");
   fprintf (stderr, "============================================================================\n");
   
   fprintf (stderr, "\n\033[01m\033[1m Overriding any 'ulimit -c 0'...\n"
                   " Setting core size to RLIM_INFINITY...\n\n"
                   " Core dumping... (use the 'core' file for gdb analysis)\033[0m\n\n");
   
   /* restore the kernel */
   neigh_enable_kernel();
   
   /* foce the coredump */
   
   setrlimit(RLIMIT_CORE, &corelimit);
   signal(sig, SIG_DFL);
   raise(sig);
#else
   sad_syslog("Ooops ! This shouldn't happen...");
   sad_syslog("Segmentation fault !");
   sad_syslog("Please recompile in debug mode and send a bugreport");
   
   exit(666);
#endif
}



RETSIGTYPE signal_TERM(int sig)
{
#ifdef HAVE_STRSIGNAL
   DEBUG_MSG("Signal handler... (caught SIGNAL: %d) | %s", sig, strsignal(sig));
#else
   DEBUG_MSG("Signal handler... (caught SIGNAL: %d)", sig);
#endif


   #ifdef HAVE_STRSIGNAL
      fprintf(stderr, "\n\n Shutting down %s (received SIGNAL: %d | %s)\n\n", GBL_PROGRAM, sig, strsignal(sig));
   #else
      fprintf(stderr, "\n\n Shutting down %s (received SIGNAL: %d)\n\n", GBL_PROGRAM, sig);
   #endif

   signal(sig, SIG_IGN);

   exit(1);

}


RETSIGTYPE signal_HUP(int sig)
{
        
   DEBUG_MSG("Signal handler got a SIGHUP... (restarting the daemon)");

   reload();

   signal(sig, signal_HUP);

}


RETSIGTYPE signal_ALRM(int sig)
{
   sad_syslog("One of the CA(s) is not responding... shutting down the daemon!");
   exit(1);
}


/* 
 * daemonize the program
 */

void daemonize(void)
{
   pid_t pid;

   DEBUG_MSG("daemonize");

#ifdef DEBUG
   /* in debug mode don't demonize.... */
   return;
#endif
   
   if((signal(SIGTTOU, SIG_IGN)) == SIG_ERR)
      ERROR_MSG("signal(SIGTTOU)");

   if((signal(SIGTTIN, SIG_IGN)) == SIG_ERR)
      ERROR_MSG("signal(SIGTTIN)");

   if((signal(SIGTSTP, SIG_IGN)) == SIG_ERR)
      ERROR_MSG("signal(SIGTSTP)");

//daveti: remove the forking
/*
   if((pid = fork()) < 0)
      ERROR_MSG("fork() during daemonization");
   else if(pid != 0) {
      fprintf(stdout, "sarpd demonized with PID: %d", pid);
      exit(0);
   }
*/

   /* here is the daemon */

//daveti: hack the daemon
/*
   if(setsid() == -1)
      ERROR_MSG("setsid()");

   close(fileno(stdin));
   close(fileno(stdout));
*/

//daveti: debug
printf("daemon is urning with PID [%d]\n", getpid());
        
}



/* EOF */

// vim:ts=3:expandtab

