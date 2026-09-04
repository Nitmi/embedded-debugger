ENTRY(Reset)

MEMORY
{
  FLASH : ORIGIN = 0x00000000, LENGTH = 1024K
  RAM   : ORIGIN = 0x20000000, LENGTH = 256K
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

  /DISCARD/ :
  {
    *(.ARM.exidx .ARM.exidx.*);
    *(.ARM.extab .ARM.extab.*);
    *(.comment);
  }
}
