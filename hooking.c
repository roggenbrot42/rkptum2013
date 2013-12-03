#include <linux/types.h>

#include "hooking.h"

// and finally, sys_call_table pointer
//sys_call_ptr_t *_sys_call_table = NULL;

void find_syscall_table() {
    // struct for IDT register contents
    struct desc_ptr idtr;

    // pointer to IDT table of desc structs
    gate_desc *idt_table;

    // gate struct for int 0x80
    gate_desc *system_call_gate;

    // system_call (int 0x80) offset and pointer
    unsigned long _system_call_off;
    unsigned long *_system_call_ptr;

    // temp variables for scan
    unsigned int i;
    u64 *off;

    // store IDT register contents directly into memory
    asm ("sidt %0" : "=m" (idtr));

    // print out location
    printk("+ IDT is at %08lx\n", idtr.address);

    // set table pointer
    idt_table = (gate_desc *) idtr.address;

    // set gate_desc for int 0x80
    system_call_gate = &idt_table[0x80];

    // get int 0x80 handler offset
    //_system_call_off = (system_call_gate->a & 0xffff) | (system_call_gate->b & 0xffff0000);
    _system_call_off = gate_offset(*system_call_gate);
    _system_call_ptr = (unsigned int *) _system_call_off;

    // print out int 0x80 handler
    printk("+ system_call is at %p\n", _system_call_off);
    printk("+ syscall_table: %p\n", syscall_table); 

    print_hex_dump(KERN_INFO, "", DUMP_PREFIX_ADDRESS, 32, 2, _system_call_ptr, 128, 1);
    print_hex_dump(KERN_INFO, "", DUMP_PREFIX_ADDRESS, 32, 2, syscall_table, 128, 1);
    // scan for known pattern in system_call (int 0x80) handler
    // pattern is just before sys_call_table address
    for(i = 0; i < 128; i++) {
        off = _system_call_ptr + i;
        if(*(off) == 0xff && *(off+1) == 0x14 && *(off+2) == 0x85) {
            printk(KERN_INFO "found sys_call_table\n");
	    _sys_call_table = *(void **)(off+3);
            break;
        }
    }

    // bail out if the scan came up empty
    if(_sys_call_table == NULL) {
        printk("- unable to locate sys_call_table\n");
        return;
    }

    // print out sys_call_table address
    printk("+ found sys_call_table at %08p!\n", _sys_call_table);

}
