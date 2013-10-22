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
#include "sysmap.h"

#define DRIVER_AUTHOR "Rootkit Programming"
#define DRIVER_DESC   "Assigment 1 - 5 LKM Programming"

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

static int __init mod_init(void)
{
  printk(KERN_INFO "Welcome!\n");
  print_nr_procs();
  print_nr_procs2();

  return 0;
}

static void __exit mod_exit(void)
{
  printk(KERN_INFO "Goodbye!\n");
}


    
module_init(mod_init);
module_exit(mod_exit);

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL");
