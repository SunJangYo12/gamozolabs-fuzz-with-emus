#include <stdint.h>

struct _registers {
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
}

inst_0000(struct _registers *regs) {
inst_0000:
    regs->rax += 5;
}
