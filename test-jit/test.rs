#![no_std]
#![feature(asm)]

pub struct Registers {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
}

#[inline(always)]
fn jumpto(pc: usize, jmptbl: usize, regs: &mut Registers) -> ! {
    unsafe {
        asm!(r#"
            // Look up PC in table
            jmp rax
        "#, options(noreturn))
    }
}

pub extern fn main(jmptbl: usize, regs: &mut Registers) {
    regs.rax += 1;
    regs.rax -= 5;
    if regs.rax > 5 {
        regs.rax += 5;
    } else {
        regs.rax -= 5;
    }

    jumpto(0x5004, jmptbl, regs)
}
