obj-m = rootkit.o

rootkit-objs += hooking.o
rootkit-objs += read_hooking.o
rootkit-objs += mod.o

KERNELBUILD = /lib/modules/$(shell uname -r)/build
default: 
	make -C $(KERNELBUILD) M=$(PWD) modules
clean:
	make -C $(KERNELBUILD) M=$(PWD) clean
