#
# Makefile of SIRENSLinux
#

EXTRA_CFLAGS	+= -Wall -Werror -I.
EXTRA_CFLAGS	+= -DIPSIRENS_MAX_ICMP=50 -DIPSIRENS_MAX_SK=50 # -DSR_DEBUG
EXTRA_CFLAGS	+= -D__linux__=1	# for Android cross tool

MODULE_BASE	= /lib/modules/$(shell uname -r)
INSTALL	?= /usr/bin/install --mode=644
DEPMOD	?= /sbin/depmod -A

ifneq ($(KERNELRELEASE),)

obj-m := ip_sirens.o

else

KERNEL_DIR ?= $(MODULE_BASE)/build
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

endif

install: ip_sirens.ko
	$(INSTALL) ip_sirens.h /usr/include/netinet/
	$(INSTALL) ip_sirens.ko  $(MODULE_BASE)/kernel/net/ipv4/
	$(DEPMOD)

clean:
	rm -f *.o .*.cmd ip_sirens.mod.c ip_sirens.ko
	rm -fr .tmp_versions Module.symvers modules.order
