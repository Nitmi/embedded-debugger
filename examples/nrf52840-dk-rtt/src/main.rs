#![no_main]
#![no_std]

mod ring;

use core::arch::{asm, global_asm};
use core::panic::PanicInfo;
use core::ptr::{addr_of_mut, read_volatile, write_volatile};

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
    cpsid i
    ldr r0, =__sidata
    ldr r1, =__sdata
    ldr r2, =__edata
1:  cmp r1, r2
    bhs 2f
    ldr r3, [r0], #4
    str r3, [r1], #4
    b 1b
2:  ldr r1, =__sbss
    ldr r2, =__ebss
    movs r3, #0
3:  cmp r1, r2
    bhs 4f
    str r3, [r1], #4
    b 3b
4:  bl rust_main
    b .
    .section .text.DefaultHandler,"ax",%progbits
    .align 2
    .global DefaultHandler
    .type DefaultHandler,%function
    .thumb_func
DefaultHandler:
    b .
"#
);

const BUFFER_BYTES: usize = 1024;
const READY: &[u8] = b"EAT_NRF52840_DK_RTT_READY v1\r\n";
const BUILD: &[u8] = concat!(
    "EAT_NRF52840_DK_RTT_BUILD_ID v1 ",
    env!("NRF_RTT_BUILD_ID"),
    "\r\n"
)
.as_bytes();
const HEARTBEAT: &[u8] = b"EAT_NRF52840_DK_RTT_HEARTBEAT ";

#[repr(C)]
struct UpChannel {
    name: u32,
    buffer: u32,
    size: u32,
    write: u32,
    read: u32,
    flags: u32,
}

#[repr(C)]
struct ControlBlock {
    magic: [u8; 16],
    up_count: u32,
    down_count: u32,
    up: UpChannel,
}

const _: [(); 48] = [(); core::mem::size_of::<ControlBlock>()];
const _: [(); 40] =
    [(); core::mem::offset_of!(ControlBlock, up) + core::mem::offset_of!(UpChannel, read)];

#[used]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".rtt.control")]
static mut _SEGGER_RTT: ControlBlock = ControlBlock {
    magic: [0; 16],
    up_count: 0,
    down_count: 0,
    up: UpChannel {
        name: 0,
        buffer: 0,
        size: 0,
        write: 0,
        read: 0,
        flags: 0,
    },
};

#[used]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".rtt.buffer")]
static mut EAT_RTT_BUFFER: [u8; BUFFER_BYTES] = [0; BUFFER_BYTES];

#[unsafe(no_mangle)]
pub extern "C" fn rust_main() -> ! {
    unsafe {
        // Development-only software unlock. Requires pre-existing compatible UICR
        // on improved-APPROTECT revisions; this image never programs UICR itself.
        write_volatile(0x4000_0558 as *mut u32, 0x5A);
        write_volatile(addr_of_mut!(_SEGGER_RTT.up_count), 1);
        write_volatile(
            addr_of_mut!(_SEGGER_RTT.up.buffer),
            addr_of_mut!(EAT_RTT_BUFFER) as u32,
        );
        write_volatile(addr_of_mut!(_SEGGER_RTT.up.size), BUFFER_BYTES as u32);
        asm!("dmb", options(nostack, preserves_flags));
        for (index, byte) in b"SEGGER RTT\0\0\0\0\0\0".iter().enumerate() {
            write_volatile(
                addr_of_mut!(_SEGGER_RTT.magic).cast::<u8>().add(index),
                *byte,
            );
        }
        let mut banner = [0_u8; 256];
        let length = identity(&mut banner);
        let _ = rtt_write(&banner[..length]);
        // A single banner fits indefinitely. No heartbeat producer runs until
        // a host consumes it; delayed attachment cannot overflow the initial ring.
        while read_volatile(addr_of_mut!(_SEGGER_RTT.up.read)) == 0 {
            asm!("nop", options(nomem, nostack, preserves_flags));
        }
        // SysTick polling at nominal 1 ms (64 MHz core), no interrupt enabled.
        write_volatile(0xE000_E014 as *mut u32, 63_999);
        write_volatile(0xE000_E018 as *mut u32, 0);
        write_volatile(0xE000_E010 as *mut u32, 5);
    }
    let mut sequence = 0_u32;
    let mut skipped = 0_u32;
    loop {
        delay_ms(250);
        sequence = sequence.wrapping_add(1);
        let mut frame = [0_u8; 256];
        let mut length = identity(&mut frame);
        append(&mut frame, &mut length, HEARTBEAT);
        hex(&mut frame, &mut length, sequence);
        append(&mut frame, &mut length, b" SKIPPED=");
        hex(&mut frame, &mut length, skipped);
        append(&mut frame, &mut length, b"\r\n");
        if !unsafe { rtt_write(&frame[..length]) } {
            skipped = skipped.wrapping_add(1);
        }
    }
}

fn identity(output: &mut [u8]) -> usize {
    let mut length = 0;
    append(output, &mut length, READY);
    append(output, &mut length, BUILD);
    length
}

fn append(output: &mut [u8], length: &mut usize, value: &[u8]) {
    output[*length..*length + value.len()].copy_from_slice(value);
    *length += value.len();
}

fn hex(output: &mut [u8], length: &mut usize, value: u32) {
    for shift in (0..8).rev() {
        let nibble = ((value >> (shift * 4)) & 15) as u8;
        output[*length] = if nibble < 10 {
            b'0' + nibble
        } else {
            b'A' + nibble - 10
        };
        *length += 1;
    }
}

unsafe fn rtt_write(bytes: &[u8]) -> bool {
    unsafe {
        let write = read_volatile(addr_of_mut!(_SEGGER_RTT.up.write)) as usize;
        let read = read_volatile(addr_of_mut!(_SEGGER_RTT.up.read)) as usize;
        let Some(reservation) = ring::reserve(BUFFER_BYTES, write, read, bytes.len()) else {
            return false;
        };
        let buffer = addr_of_mut!(EAT_RTT_BUFFER).cast::<u8>();
        for (index, byte) in bytes[..reservation.first].iter().enumerate() {
            write_volatile(buffer.add(write + index), *byte);
        }
        for (index, byte) in bytes[reservation.first..].iter().enumerate() {
            write_volatile(buffer.add(index), *byte);
        }
        asm!("dmb", options(nostack, preserves_flags));
        write_volatile(
            addr_of_mut!(_SEGGER_RTT.up.write),
            reservation.next_write as u32,
        );
        true
    }
}

fn delay_ms(milliseconds: u32) {
    for _ in 0..milliseconds {
        while unsafe { read_volatile(0xE000_E010 as *const u32) } & (1 << 16) == 0 {
            unsafe { asm!("nop", options(nomem, nostack, preserves_flags)) };
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        unsafe { asm!("nop", options(nomem, nostack, preserves_flags)) };
    }
}
