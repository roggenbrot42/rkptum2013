#include<linux/module.h>
#include<linux/sched.h>
#include<linux/kthread.h>

int hiding_thread(void * data){
	printk(KERN_INFO "Kernel thread called\n");
	return 0;
}

void hide_code(void){
	kthread_run(hiding_thread, NULL, "dontlookatme");
}
