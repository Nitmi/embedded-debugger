#![no_main]
#![no_std]

use core::arch::{asm, global_asm};
use core::panic::PanicInfo;
use core::ptr::{read_volatile, write_volatile};

global_asm!(
    r#"
    .syntax unified
    .cpu cortex-m4
    .thumb

    .section .vector_table,"a",%progbits
    .align 2
    .global VECTOR_TABLE
VECTOR_TABLE:
    .word 0x20040000
    .word Reset
    .rept 62
    .word DefaultHandler
    .endr

    .section .text.Reset,"ax",%progbits
    .align 2
    .global Reset
    .type Reset,%function
    .thumb_func
Reset:
    bl rust_main
1:
    b 1b

    .section .text.DefaultHandler,"ax",%progbits
    .align 2
    .global DefaultHandler
    .type DefaultHandler,%function
    .thumb_func
DefaultHandler:
2:
    b 2b
"#
);

const GPIO_P0_BASE: usize = 0x5000_0000;
const GPIO_OUTSET: usize = GPIO_P0_BASE + 0x508;
const GPIO_OUTCLR: usize = GPIO_P0_BASE + 0x50C;
const GPIO_DIRSET: usize = GPIO_P0_BASE + 0x518;
const GPIO_PIN_CNF_0: usize = GPIO_P0_BASE + 0x700;

const UART0_BASE: usize = 0x4000_2000;
const UART_TASKS_STARTTX: usize = UART0_BASE + 0x008;
const UART_EVENTS_TXDRDY: usize = UART0_BASE + 0x11C;
const UART_ENABLE: usize = UART0_BASE + 0x500;
const UART_PSEL_RTS: usize = UART0_BASE + 0x508;
const UART_PSEL_TXD: usize = UART0_BASE + 0x50C;
const UART_PSEL_CTS: usize = UART0_BASE + 0x510;
const UART_PSEL_RXD: usize = UART0_BASE + 0x514;
const UART_TXD: usize = UART0_BASE + 0x51C;
const UART_BAUDRATE: usize = UART0_BASE + 0x524;
const UART_CONFIG: usize = UART0_BASE + 0x56C;

const APPROTECT_DISABLE: usize = 0x4000_0558;
const APPROTECT_SW_DISABLE: u32 = 0x5A;

const LED1_PIN: u32 = 13;
const UART_TX_PIN: u32 = 6;
const PIN_DISCONNECTED: u32 = 0xFFFF_FFFF;
const UART_BAUD_115200: u32 = 0x01D7_E000;

const READY: &[u8] = b"EAT_NRF52840_DK_READY v1\r\n";
const BUILD_ID: &[u8] = concat!(
    "EAT_NRF52840_DK_BUILD_ID v1 ",
    env!("NRF_SMOKE_BUILD_ID"),
    "\r\n"
)
.as_bytes();
const HEARTBEAT: &[u8] = b"EAT_NRF52840_DK_HEARTBEAT\r\n";

// nRF52840 Fxx and later need both this UICR value and the runtime write below
// to keep development debug access available across resets.
#[used]
#[unsafe(link_section = ".uicr.approtect")]
static UICR_APPROTECT_HW_DISABLED: u32 = 0x0000_005A;

#[unsafe(no_mangle)]
pub extern "C" fn rust_main() -> ! {
    unsafe {
        mmio_write(APPROTECT_DISABLE, APPROTECT_SW_DISABLE);
        led_init();
        uart_init();
        uart_write(READY);
        uart_write(BUILD_ID);
    }

    let mut led_on = false;
    loop {
        delay();
        led_on = !led_on;
        unsafe {
            led_set(led_on);
            uart_write(HEARTBEAT);
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        unsafe { asm!("bkpt", options(nomem, nostack, preserves_flags)) };
    }
}

unsafe fn led_init() {
    let led_mask = 1_u32 << LED1_PIN;
    unsafe {
        mmio_write(GPIO_OUTSET, led_mask);
        mmio_write(GPIO_PIN_CNF_0 + LED1_PIN as usize * 4, 0x0000_0003);
        mmio_write(GPIO_DIRSET, led_mask);
    }
}

unsafe fn led_set(on: bool) {
    let register = if on { GPIO_OUTCLR } else { GPIO_OUTSET };
    unsafe { mmio_write(register, 1_u32 << LED1_PIN) };
}

unsafe fn uart_init() {
    unsafe {
        mmio_write(UART_ENABLE, 0);
        mmio_write(UART_PSEL_RTS, PIN_DISCONNECTED);
        mmio_write(UART_PSEL_CTS, PIN_DISCONNECTED);
        mmio_write(UART_PSEL_RXD, PIN_DISCONNECTED);
        mmio_write(UART_PSEL_TXD, UART_TX_PIN);
        mmio_write(UART_BAUDRATE, UART_BAUD_115200);
        mmio_write(UART_CONFIG, 0);
        mmio_write(UART_ENABLE, 4);
        mmio_write(UART_TASKS_STARTTX, 1);
    }
}

unsafe fn uart_write(bytes: &[u8]) {
    for &byte in bytes {
        unsafe {
            mmio_write(UART_EVENTS_TXDRDY, 0);
            mmio_write(UART_TXD, u32::from(byte));
            while mmio_read(UART_EVENTS_TXDRDY) == 0 {
                asm!("nop", options(nomem, nostack, preserves_flags));
            }
        }
    }
}

fn delay() {
    for _ in 0..4_000_000 {
        unsafe { asm!("nop", options(nomem, nostack, preserves_flags)) };
    }
}

unsafe fn mmio_write(address: usize, value: u32) {
    unsafe { write_volatile(address as *mut u32, value) };
}

unsafe fn mmio_read(address: usize) -> u32 {
    unsafe { read_volatile(address as *const u32) }
}
