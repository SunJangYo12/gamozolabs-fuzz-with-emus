#![feature(asm, naked_functions)]
#![no_std]

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

#[naked]
pub extern "C" fn main(jmptbl: usize, regs: &mut Registers) {
//    regs.rax += 1;
//    regs.rax -= 5;
    if regs.rax > 5 {
        jumpto(0x19000, jmptbl, regs)
    } else {
        jumpto(0x5004, jmptbl, regs)
    }

}
