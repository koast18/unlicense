/* Spike 1 target: a tiny, deterministic binary whose code shape lets the
 * Frida agent locate specific instructions by the immediates they embed.
 *
 * The agent must answer, on the real target platform (Windows ia32/x64 and,
 * for fast local iteration, Linux x64):
 *   - does Stalker.follow + transform + putCallout fire at all
 *   - can we read mnemonic / size / operands / next from a traced instruction
 *   - can we compute an effective address from X86Operand + CpuContext and
 *     have it match the real address of an exported global
 *   - can we read and WRITE CpuContext registers from a callout
 *   - can we read and WRITE CpuContext.eflags from a callout (and does the
 *     written ZF actually steer the following conditional jump)
 *   - can we WRITE the program counter from a callout (ExecuteAt primitive)
 *   - can we read raw instruction bytes (the stage-2 modrm decode)
 *   - can we write process memory from a callout
 *
 * Every observable lands on stdout in the final DONE line; the agent reports
 * what it saw. The target blocks until the host creates the go-file so the
 * agent can install instrumentation before any of this code runs.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#  include <windows.h>
#  define EXPORT __declspec(dllexport)
#  define NOINLINE __declspec(noinline)
#else
#  include <unistd.h>
#  define EXPORT __attribute__((visibility("default")))
#  define NOINLINE __attribute__((noinline))
#endif

#define MAGIC_START 0x11223344u
#define MAGIC_EQ 0xAABBCCDDu
#define STORE_IMM 0x55667788u
#define PC_IMM 0x11111111u
#define REG_IMM 0x12345678u
#define GO_FILE "spike_go"
#define EXIT_FILE "spike_exit"

EXPORT volatile uint32_t g_magic = MAGIC_START;
EXPORT volatile uint32_t g_flag = 0u;
EXPORT volatile uint32_t g_hits = 0u;
EXPORT volatile uint32_t g_sink = 0u;
EXPORT volatile uint32_t g_sink2 = 0u;
EXPORT volatile uint32_t g_taken = 0u;
EXPORT volatile uint32_t g_sink3 = 0u;

/* cmp against an immediate -> comparison-neutralisation test (the agent
 * rewrites the compared register or the memory it reads) */
EXPORT NOINLINE void spike_branch_test(void) {
    if (g_magic == MAGIC_EQ) {
        g_flag = 1u;
        g_taken++;
    }
}

/* single store of a unique immediate -> EA computation test */
EXPORT NOINLINE void spike_store_test(void) {
    g_sink = STORE_IMM;
}

/* single store of a unique immediate; the agent skips it by rewriting pc */
EXPORT NOINLINE void spike_pc_test(void) {
    g_sink2 = PC_IMM;
}

/* single store of a unique immediate; skipped via Interceptor pc rewrite */
EXPORT NOINLINE void spike_pc2_test(void) {
    g_sink3 = 0x33333333u;
}

/* returns a unique immediate in a register -> register write test */
EXPORT NOINLINE uint32_t spike_reg_test(void) {
    return REG_IMM;
}

static void wait_for_file(const char *path) {
    for (int i = 0; i < 900; i++) {
        FILE *f = fopen(path, "rb");
        if (f != NULL) {
            fclose(f);
            return;
        }
#if defined(_WIN32)
        Sleep(50);
#else
        usleep(50000);
#endif
    }
}

int main(void) {
    uint32_t reg;
    int i;

    printf("SPIKE_TARGET bits=%d\n", (int)(sizeof(void *) * 8));
    printf("ADDR g_magic=%p g_flag=%p g_sink=%p g_sink2=%p g_sink3=%p\n",
           (void *)&g_magic, (void *)&g_flag, (void *)&g_sink,
           (void *)&g_sink2, (void *)&g_sink3);
    printf("FUNC branch=%p store=%p pc=%p pc2=%p reg=%p\n",
           (void *)&spike_branch_test, (void *)&spike_store_test,
           (void *)&spike_pc_test, (void *)&spike_pc2_test,
           (void *)&spike_reg_test);
    fflush(stdout);

    wait_for_file(GO_FILE);

    g_sink = 0u;
    g_sink2 = 0u;
    g_sink3 = 0u;
    spike_store_test();
    spike_pc_test();
    spike_pc2_test();
    reg = spike_reg_test();
    for (i = 0; i < 8; i++) {
        spike_branch_test();
        g_hits++;
    }

    printf("DONE g_flag=%u g_taken=%u g_hits=%u g_sink=%08x g_sink2=%08x "
           "g_sink3=%08x reg=%08x magic=%08x\n",
           g_flag, g_taken, g_hits, g_sink, g_sink2, g_sink3, reg, g_magic);
    fflush(stdout);

    /* Hold the process open until the host has read the agent's report:
     * the finish() RPC must run against a live process. */
    wait_for_file(EXIT_FILE);
    return 0;
}
