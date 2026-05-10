#include <stdint.h>

struct _registers {
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
};

void jmpout() {
}

void inst_0000(struct _registers *regs) {
inst_0000:
    regs->rax += 1;
inst_0004:
    regs->rax -= 5;
inst_0008:
    if (regs->rax != 0) {
        goto inst_0010;
    }
inst_000c:
    jmpout();
inst_0010:
    regs->rax = 17;
    jmpout();
}
