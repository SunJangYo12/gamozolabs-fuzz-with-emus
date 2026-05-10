#include <stdint.h>

struct _registers {
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
};

uint64_t inst_0000(void *jmptbl, struct _registers *regs) {
inst_0000:
    regs->rax += 1;
    goto inst_0004;
inst_0004:
    regs->rax -= 5;
    goto inst_0008;
inst_0008:
    if (regs->rax != 0) {
        goto inst_0010;
    }
    goto inst_000c;
inst_000c:
    return 0x5483;
    goto inst_0010;
inst_0010:
    regs->rax = 17;
    return 0x54833429;
}
