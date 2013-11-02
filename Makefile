obj-m = rootkit.o

rootkit-objs += process_hiding.o
rootkit-objs += mod.o

KERNELBUILD = /lib/modules/$(shell uname -r)/build

default: sysmap.h
	make -C $(KERNELBUILD) M=$(PWD) modules
sysmap.h:
	sh ./sysmap.sh
clean:
	make -C $(KERNELBUILD) M=$(PWD) clean
	rm -f sysmap.h
