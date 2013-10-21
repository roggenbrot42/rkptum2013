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
#include <linux/init.h> /* Needed for the macros */
#include <linux/sched.h>
#include "sysmap.h"

#define DRIVER_AUTHOR "Rootkit Programming"
#define DRIVER_DESC   "Assigment 1 - 5 LKM Programming"

static void print_nr_procs(void)
{
  printk(KERN_INFO "Number of current running processes: %d", nr_processes());
}

static int __init mod_init(void)
{
  printk(KERN_INFO "Welcome!\n");
  printk(KERN_INFO "Number of current running processes: %d", nr_processes());
  print_nr_procs();

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
