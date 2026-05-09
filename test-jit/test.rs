#![no_std]
#![feature(asm)]

pub struct Registers {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
}

#[inline(always)]
fn noret() -> ! {
    unsafe { asm!(".byte 0x41, 0x41, 0x41, 0x41", options(noreturn)) }
}

pub fn main(regs: &mut Registers) {
    regs.rax += 1;
    regs.rax -= 5;
    if regs.rax > 5 {
        regs.rax += 5;
    } else {
        regs.rax -= 5;
    }

    noret();
}
