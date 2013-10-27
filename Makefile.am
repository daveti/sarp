
include $(top_srcdir)/Makefile.am.common

SUBDIRS = man src include 

EXTRA_DIST = LICENSE \
             AUTHOR \
             CHANGELOG \
             Makefile.am.common \
             shtool \
             packaging/rpm/sarpd.spec.in \
             kernel/patch/sarp-2.4.18.diff \
             kernel/module/Makefile.in \
             kernel/module/sarp.c \
             etc/init.d/sarpd.in \
             etc/sarpd/sarpd_conf \
             etc/sarpd/known_hosts \
             etc/sarpd/hosts

CLEANFILES = *.log *.out

module:
	cd kernel/module && make

module_install:
	cd kernel/module && make install

install-data-hook:
	$(INSTALL) -d /etc/sarpd
	$(INSTALL) -d /etc/sarpd/hosts
	$(INSTALL) -m 644 etc/sarpd/sarpd_conf /etc/sarpd
	$(INSTALL) -m 644 etc/sarpd/known_hosts /etc/sarpd

uninstall-hook:
	rm -Rf /etc/sarpd
	cd kernel/module && make uninstall

# vim:ts=4:noexpandtab
