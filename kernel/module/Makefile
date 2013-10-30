
CC = gcc
INSTALL = /usr/bin/install -c

CFLAGS = -O2 -Wall -DARP_PACKET_TYPE_ADDR=`grep -w arp_packet_type /boot/System.map | awk {'print "0x"$$1'}`

all:
	$(CC) -c -I/usr/src/linux/include $(CFLAGS) sarp.c -o sarp.o

install:
	$(INSTALL) -d /lib/modules/`uname -r`/kernel/net/ipv4
	$(INSTALL) -m 644 sarp.o /lib/modules/`uname -r`/kernel/net/ipv4

uninstall:
	rm -f /lib/modules/`uname -r`/kernel/net/ipv4

# vim:ts=4:noexpandtab
