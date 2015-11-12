# Makefile for tcp_relentless.c
# this includes an implicit Kbuild, per Documentation/kbuild/modules.txt

ifneq ($(KERNELRELEASE),)
# the kbuild imbedded in this makefile
obj-m := tcp_relentless.o

else
# The real Makefile is nearly empty

KERNELDIR := /lib/modules/`uname -r`/build
all::
	$(MAKE) -C $(KERNELDIR) M=`pwd` $@

clean:
	rm -f *.o *.ko .tcp*.o Module.symvers

# that's all folks
endif
