#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */
#include <linux/syscalls.h>
#include <linux/types.h>
#include "hooking.h"

struct idtr_struct{
      u16 limit;
      u64 base;
} __attribute__((packed)) idtr;


struct idt_struct{
      u16 off1;
      u16 sel;
      unsigned char none;
      unsigned char flags;
      u16 off2;
} __attribute__((packed));

struct idt_struct __attribute__((packed)) * idt;

void ** find_syscall_table(void)
{
    //u64 sys_call_off;
    //u64 sys_call_handler;
    //u64 sys_call_table;
    //unsigned char* p;
    //unsigned char *limit;
    //int ii,i;
    //unsigned long other_addr;
    // printk("get value %x\n", sys_call_table_R);
    //rdmsrl(MSR_LSTAR, other_addr);

    //printk("other addr: %x\n", other_addr);
    //// get idtr address
    //asm("rip %0":"=m"(sys_call_handler));
    //printk("addr of idtr: %x\n", &idtr);
    //// get syscall handel address
    //idt = (struct idt_struct *)(idtr.base)+0x80;
    //sys_call_off = ((idt->off2) << 16) | (idt->off1);
    ////printk("off 1 %x\n", idt->off1);

    ////sys_call_off=(((idt->off2) << 16) | idt->off1);
    //// search sys_call_table adress
    //p=(unsigned char *)sys_call_off;
    ////p=(unsigned char *)sys_call_off;
    //for (i=0; i<0x100; i++)
    // {
    //     //printk("p: %x\n", p);
    //     if (*p==0xff && *(p+1)==0x14 && *(p+2)==0xc5)
    //     {
    //         sys_call_table=*((u64 *)p+3);
    //         printk("addr of sys_call_table: %x\n", sys_call_table);
    //         return ;
    //     }
    //     p++;
    // }
    u64 ptr = sys_close;
    u64 i =0;
    u64 *p;
    printk(KERN_INFO "sys close %x\n", ptr);
  for (i=0; i<6400000; i++){
    p = (void *)ptr;
    if (p[__NR_close] == sys_close){
      printk(KERN_INFO "found the sys_call_table!!!\n");
      return (void **)p;
    }
    ptr += 1;
  }
  return NULL;
}
