#include <tuple>
#include <stdint.h>

enum _exitcodes {
    IndirectBranch = 0,
};

struct _registers {
    uint64_t exitcode;
    uint64_t exitinfo;

    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
};

extern "C" void _start(void *jmptbl, struct _registers *regs) {
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
    regs->exitcode = IndirectBranch;
    regs->exitinfo = 1241299;
    return;
    goto inst_0010;
inst_0010:
    regs->rax = 17;
    regs->exitcode = IndirectBranch;
    regs->exitinfo = 12412;
    return;
}
