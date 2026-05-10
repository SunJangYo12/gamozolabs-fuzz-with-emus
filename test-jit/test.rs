#![feature(asm, naked_functions)]
#![no_std]

#![allow(unused_labels)]

#[repr(C)]
pub struct Registers {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,

    ra: u64,
}

#[inline(always)]
fn jumpto(pc: usize, jmptbl: usize, regs: &mut Registers) -> ! {
    unsafe {
        asm!(r#"
            // Look up PC in table
            add {jmptbl}, {pc}
            jmp {jmptbl}
            mov rdi, {foo}
        "#, pc = in(reg) pc,
            jmptbl = in(reg) jmptbl,
            foo = in(reg) regs,
            options(noreturn))
    }
}

//#[naked]
pub extern "C" fn main(jmptbl: usize, regs: &mut Registers) {
    // 0000 add rax, 1
    // 0004 sub rax, 5
    // 0008 bnez rax, 0000
    // 000c ret

    // start loop
    'inst_0000: loop {
        regs.rax += 1;

        'inst_0004: loop {
            regs.rax -= 5;

            'inst_0008: loop {
                if regs.rax != 0 {
                    jumpto(0x0000, jmptbl, regs);
                }

                'inst_000c: loop {
                    jumpto(regs.ra as usize, jmptbl, regs);
                }
            }
        }
    }
}
