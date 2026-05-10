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
inst_0000:
    regs->rax += 1;
inst_0004:
    regs->rax -= 5;
inst_0008:
    if (regs->rax != 0) {
        goto inst_0010;
    }
inst_000c:
    jmpout(jmptbl, regs);
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

    for( ; ; );
}
