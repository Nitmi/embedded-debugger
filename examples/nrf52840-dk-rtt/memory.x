ENTRY(Reset)
MEMORY
{
  FLASH : ORIGIN = 0x00000000, LENGTH = 1024K
  RAM   : ORIGIN = 0x20000000, LENGTH = 256K
}
SECTIONS
{
  .vector_table ORIGIN(FLASH) : ALIGN(4) { KEEP(*(.vector_table)); } > FLASH
  .text : ALIGN(4) { *(.text .text.*); *(.rodata .rodata.*); } > FLASH
  .data : ALIGN(4)
  {
    __sdata = .;
    *(.data .data.*);
    . = ALIGN(4);
    __edata = .;
  } > RAM AT > FLASH
  __sidata = LOADADDR(.data);
  .bss (NOLOAD) : ALIGN(4)
  {
    __sbss = .;
    KEEP(*(.rtt.control));
    KEEP(*(.rtt.buffer));
    *(.bss .bss.*); *(COMMON);
    . = ALIGN(4);
    __ebss = .;
  } > RAM
  ASSERT(__ebss < 0x2003F000, "RAM leaves less than 4 KiB for stack")
  /DISCARD/ : { *(.ARM.exidx .ARM.exidx.*); *(.ARM.extab .ARM.extab.*); *(.comment); }
}
