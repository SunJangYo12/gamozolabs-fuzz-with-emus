#include <stdint.h>

struct _registers {
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
};


__attribute__((always_inline))
_Noreturn
static void jmpout(void *jmptbl, struct _registers *regs);

_Noreturn
void inst_0000(void *jmptbl, struct _registers *regs) {
    volatile char foo[1024];

inst_0000:
    regs->rax += 1;
    goto inst_0004;
inst_0004:
    regs->rax -= 5;
    goto inst_0008;
inst_0008:
    if (regs->rax != 0) {
        foo[53] = 6;
        goto inst_0010;
    }
    goto inst_000c;
inst_000c:
    jmpout(jmptbl, regs);
    goto inst_0010;
inst_0010:
    regs->rax = 17;
    jmpout(jmptbl, regs);
}


__attribute__((always_inline))
_Noreturn
static void jmpout(void *jmptbl, struct _registers *regs) {
    asm volatile(R"goodstr(
        int3
    )goodstr");

    __builtin_unreachable();
}
