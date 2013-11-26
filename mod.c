#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */
#include <linux/init.h> /* Needed for the macros, hints for linking and loading, see http://tldp.org/LDP/lkmpg/2.6/html/x245.html */

#include "commands.h"
#include "sysmap.h"

#define DRIVER_AUTHOR "Nicolas Appel, Wenwen Chen"
#define DRIVER_DESC   "Assigment 7"

static int __init mod_init(void)
{
  listen();
  printk(KERN_INFO "mod_init\n");
  return 0;
}

static void __exit mod_exit(void)
{
  stop_listen();
}



module_init(mod_init);
module_exit(mod_exit);

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL");

