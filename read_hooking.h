#ifndef READ_HOOKING_H
#define READ_HOOKING_H

#include <linux/types.h>
#include <asm/unistd.h>
#include <linux/kernel.h> /* Needed for KERN_INFO */
#include<linux/kthread.h>



void hook_read(void);
void unhook_read(void);

#endif
