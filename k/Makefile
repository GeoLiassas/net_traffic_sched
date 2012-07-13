#obj-m += k_flow_control.o
#all:
#	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
#clean:
#	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean




# Makefile for the k_flow_control module (k_flow_control.c)

obj-m += k_flow_control.o
BASEDIR	= ~/nexusKernel
export BASEDIR
KDIR	= samsung/#kernel
export KDIR
PWD = `pwd`
export PWD

all:
	make ARCH=arm CROSS_COMPILE=$(CROSS_COMPILE) -C $(BASEDIR)/$(KDIR) M=$(PWD) modules

clean:
	make ARCH=arm CROSS_COMPILE=$(CROSS_COMPILE) -C $(BASEDIR)/$(KDIR) M=$(PWD) clean
