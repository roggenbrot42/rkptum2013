/*  
 *  mod.c - The first kernel module.
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
//#include <linux/list.h>
// Why can nr_processes be called directly?
#include <linux/sched.h>
#include <asm/cacheflush.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/string.h>
#include "sysmap.h"

#define DRIVER_AUTHOR "Nicolas Appel, Wenwen Chen"
#define DRIVER_DESC   "Assigment 2 - System Call Hooking"

void ** syscall_table = (void * *) sys_call_table_R;
ssize_t (*orig_sys_read)(int fd, void *buf, size_t count);
char * buffer;

static void print_nr_procs2(void)
{
	int i=0;
  // traversing scheduler linked list
	struct task_struct *task;
	for_each_process(task)
	{
		i++;
	}
	printk(KERN_INFO "Number of current running processes (traversing scheduler linked list): %d\n", i);
}

static void print_nr_procs(void)
{
  // cast system symbol adress to function pointer
  int a = ((int (*)(void))nr_processes_T)();
  printk(KERN_INFO "Number of current running processes (cast system symbol adress to function pointer): %d\n", a);
}

static ssize_t my_read(int fd, void *buf, size_t count){
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
			printk(KERN_INFO "%s\n",buffer);
		}
	}
	return retVal;
}


static int __init mod_init(void)
{
  unsigned long addr;
  int ret;
  unsigned long cr0;


  printk(KERN_INFO "Welcome!\n");
  printk(KERN_INFO "Read address: %p", syscall_table[0]);
  
  //Disable write protection in the cpu
  cr0 = read_cr0();
  write_cr0(cr0 & ~0x00010000); //Bit 16 is the write protection bit
 

  addr = (unsigned long) syscall_table;
  //Set the memory of addr's page and the next two pages as writable
  ret = set_memory_rw(PAGE_ALIGN(addr) - PAGE_SIZE, 3);
  if(ret){
	printk(KERN_INFO "Cannot set memory to rw\n");
  }
  else{
  	printk(KERN_INFO "Set memory to rw\n");
  }

  orig_sys_read = syscall_table[__NR_read];
  syscall_table[__NR_read] = my_read;

  write_cr0(cr0);

  return 0;
}

static void __exit mod_exit(void)
{
  unsigned long cr0;
  cr0 = read_cr0();
  write_cr0(cr0 & ~0x00010000);
  syscall_table[__NR_read] = orig_sys_read;
  write_cr0(cr0);
  kfree(buffer);
  printk(KERN_INFO "Goodbye!\n");
}


    
module_init(mod_init);
module_exit(mod_exit);

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL");
