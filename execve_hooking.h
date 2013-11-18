#ifndef EXECVE_HOOKING_H
#define EXECVE_HOOKING_H

#include <linux/types.h>
#include <asm/unistd.h>
#include <linux/kernel.h> /* Needed for KERN_INFO */
#include<linux/kthread.h>



void hook_execve(void);
void unhook_execve(void);

#endif
