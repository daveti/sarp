# Oct 31, 2013
# daveti@cs.uoregon.edu
# http://davejingtian.org

CC = gcc
INSTALL = /usr/bin/install -c

# daveti: update the system.map
#CFLAGS = -O2 -Wall -DARP_PACKET_TYPE_ADDR=`grep -w arp_packet_type /boot/System.map | awk {'print "0x"$$1'}`
KVER	:= $(shell uname -r)
# daveti: use ccflags-y
#CFLAGS = -O2 -Wall -DARP_PACKET_TYPE_ADDR=`grep -w arp_packet_type /boot/System.map-$(KVER) | awk {'print "0x"$$1'}`
ccflags-y += -O2 -Wall -DARP_PACKET_TYPE_ADDR=`grep -w arp_packet_type /boot/System.map-$(KVER) | awk {'print "0x"$$1'}`

# daveti: kernel module make update
#all:
#	$(CC) -c -I/usr/src/linux/include $(CFLAGS) sarp.c -o sarp.o
ifneq ($(KERNELRELEASE),) 
obj-m	:= sarp.o

else
KDIR	:= /lib/modules/$(shell uname -r)/build
PWD	:= $(shell pwd)

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
endif

install:
	$(INSTALL) -d /lib/modules/`uname -r`/kernel/net/ipv4
	$(INSTALL) -m 644 sarp.o /lib/modules/`uname -r`/kernel/net/ipv4

uninstall:
	rm -f /lib/modules/`uname -r`/kernel/net/ipv4

# daveti: add clean
clean:
	rm *.o *.ko *~

# vim:ts=4:noexpandtab
