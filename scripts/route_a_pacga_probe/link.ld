ENTRY(_start)
SECTIONS
{
    . = 0x40080000;
    .text : { KEEP(*(.text.boot)) *(.text .text.*) }
    .rodata : { *(.rodata .rodata.*) }
    .data : { *(.data .data.*) }
    . = ALIGN(16);
    _bss_start = .;
    .bss (NOLOAD) : { *(.bss .bss.* COMMON) }
    . = ALIGN(16);
    _bss_end = .;
    . += 0x10000;
    _stack_top = .;
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
