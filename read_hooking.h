#ifndef READ_HOOKING_H
#define READ_HOOKING_H


extern void hook_read(void ** syscall_table);
extern void unhook_read(void ** syscall_table);

#endif
