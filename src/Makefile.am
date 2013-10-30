
include $(top_srcdir)/Makefile.am.common

sbin_PROGRAMS = sarpd sarp

sarpd_SOURCES = sad_main.c \
                sad_debug.c \
                sad_error.c \
                sad_signal.c \
                sad_globals.c \
                sad_parser.c \
                sad_syslog.c \
                sad_capture.c \
                sad_conf.c \
                sad_hash.c \
                sad_sarp.c \
                sad_neigh.c \
                sad_inet.c \
                sad_crypto.c \
                sarp_crypto.c \
                sad_key.c \
                missing/strlcpy.c \
                missing/strlcat.c

sarpd_CFLAGS = @SAD_CFLAGS@

sarpd_LDADD = @SAD_LIBS@

CLEANFILES = *.log *.out core.*

sarp_SOURCES = sarp_main.c \
               sarp_error.c \
               sarp_parser.c \
               sarp_globals.c \
               sarp_crypto.c 

sarp_CFLAGS = @SARP_CFLAGS@

sarp_LDADD = @SARP_LIBS@

