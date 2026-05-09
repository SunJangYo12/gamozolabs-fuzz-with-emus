#![no_std]

pub struct Registers {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
}

static FOO: u64 = 5;

pub fn main(regs: &mut Registers) {
    regs.rax += 1;
    regs.rax -= 5;
    //regs.rax += unsafe { FOO };
}
