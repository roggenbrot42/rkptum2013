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
#include <linux/sched.h>
void print_nr_procs()
{
  printk(KERN_INFO "Number of current running processes: %d", nr_processes());
}

int init_module(void)
{
  printk(KERN_INFO "Welcome!\n");
  print_nr_procs();
  return 0;
}

void cleanup_module(void)
{
  printk(KERN_INFO "Goodbye!\n");
}

