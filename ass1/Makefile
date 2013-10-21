#obj-m +=mod.o
obj-m = mod2.o
KERNELBUILD = /lib/modules/$(shell uname -r)/build
default:
	make -C $(KERNELBUILD) M=$(PWD) modules
clean:
	make -C $(KERNELBUILD) M=$(PWD) clean
