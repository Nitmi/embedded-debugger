ENTRY(Reset)

MEMORY
{
  FLASH : ORIGIN = 0x00000000, LENGTH = 1024K
  RAM   : ORIGIN = 0x20000000, LENGTH = 256K
  UICR  : ORIGIN = 0x10001000, LENGTH = 4K
}

SECTIONS
{
  .vector_table ORIGIN(FLASH) : ALIGN(4)
  {
    KEEP(*(.vector_table));
  } > FLASH

  .text : ALIGN(4)
  {
    *(.text .text.*);
    *(.rodata .rodata.*);
  } > FLASH

  .data : ALIGN(4)
  {
    *(.data .data.*);
  } > RAM AT > FLASH

  .bss (NOLOAD) : ALIGN(4)
  {
    *(.bss .bss.*);
    *(COMMON);
  } > RAM

  .uicr ORIGIN(UICR) + 0x208 : ALIGN(4)
  {
    KEEP(*(.uicr.approtect));
  } > UICR

  /DISCARD/ :
  {
    *(.ARM.exidx .ARM.exidx.*);
    *(.ARM.extab .ARM.extab.*);
    *(.comment);
  }
}
