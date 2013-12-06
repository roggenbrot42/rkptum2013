#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <asm/desc_defs.h>
#include <asm/pgtable.h>

#include "hooking.h"

void ** syscall_tab = NULL;

void ** find_syscall_table() {
	unsigned long syscall_handler_addr;
	unsigned char * p;

	unsigned char* limit;
	unsigned int * table;	

	rdmsrl(MSR_LSTAR, syscall_handler_addr);
	limit = (unsigned char*) syscall_handler_addr + 128;	
	
	for(p = (unsigned char*) syscall_handler_addr; (u64)p < (u64) limit; p++){
		/*
		* IA64 opcode for: "call *syscall_table(,%rax,8)" see arch/x86/kernel/entry_64.S:629
		* 0xFF Call
		* 0x14 ModRM: .mod=00 (register indirect addressing), 
		*		.reg=100 (use sib), .rm=101 (rip relative addressing)
		* 0xC5 SIB: scale: 11 (2^3), index: 000 (RAX), base: 101 (disp32)
		*/
		if(*p == 0xFF && *(p+1) == 0x14 &&  *(p+2) == 0xC5){
			table = (unsigned int*) (p+3);
			printk(KERN_INFO "syscall table found at: %p\n", (void*)syscall_tab);
			return (void **) *table;
		}
	}
	return NULL;
}

/*
* Interface to retrieve syscall_tab, because I'm too stupid for that now.
*/
void ** get_syscall_table(void){
	if(syscall_tab == NULL)
		syscall_tab = find_syscall_table();
	return syscall_tab;
}

inline void ** syscall_table(){
	return get_syscall_table();
}
