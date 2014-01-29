#ifndef CODE_HIDING_H
#define CODE_HIDING_H

#include<linux/module.h>
#include<linux/sched.h>
#include<linux/kthread.h>
#include<linux/mutex.h>
#include<linux/list.h>
#include<linux/string.h>
#include<linux/sysfs.h>
#include<linux/moduleparam.h>
#include<linux/dynamic_debug.h>
#include<linux/kobject.h>
#include<linux/slab.h>


void hide_code(void);
int unhide_code(void * data);

//extern void hide_code(void);
//extern void unhide_code(void);
extern int make_module_removable(void * data);
#endif
