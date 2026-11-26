OUTPUT_ARCH(aarch64)
ENTRY(_start)
SECTIONS { . = 0x40080000; .text : { *(.text) } /DISCARD/ : { *(.comment) *(.note*) } }
