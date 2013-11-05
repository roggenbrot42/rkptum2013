#ifndef HOOKING_H
#define HOOKING_H

#include <asm/processor-flags.h>
#include "sysmap.h"

static inline void disable_wp(void){
	write_cr0(read_cr0() & ~0x00010000);
}

static inline void enable_wp(void){
	write_cr0(read_cr0() | 0x00010000);
}

static void ** syscall_table = (void * *) sys_call_table_R;

#endif
