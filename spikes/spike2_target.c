/* Spike 2 target: mimics the WinLicense license-file flow so the Stage 0
 * port can be verified end to end without a real sample:
 *
 *   open the license file  ->  map it  ->  copy it BYTE BY BYTE into a heap
 *   buffer  ->  unmap the original  ->  keep the copy
 *
 * On Windows it goes through exactly the API set the PIN tool hooks
 * (CreateFileA -> NtCreateFile, CreateFileMappingA, MapViewOfFile,
 * UnmapViewOfFile); on Linux through open/mmap/munmap. The byte-at-a-time
 * copy is the pattern Stage 0 records candidate addresses from, so it must
 * survive optimization: the pointers are volatile and the loop is written
 * so no compiler can turn it into a memcpy.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#  include <windows.h>
#else
#  include <fcntl.h>
#  include <sys/mman.h>
#  include <sys/stat.h>
#  include <unistd.h>
#endif

/* ---- RSA-chain mimic --------------------------------------------------
 * Stage 1's sub-stages 2-5 walk back from the license read: that read is
 * inside mp_read_unsigned_bin, its caller is rsa_exptmod, and the next
 * direct call made by rsa_exptmod is mp_exptmod (whatlicense counts reads
 * of a local key pointer at [ebp+0x1c] to know the call is coming; this
 * port scans for the E8 instead). Reproducing that shape is what lets the
 * whole stage be validated without a cooperating real sample -- the real
 * one (drchost) never reaches its license check inside a CI VM, and the
 * canonical license-required sample from issue #45 is gone.
 */

#if defined(_MSC_VER)
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE __attribute__((noinline))
#endif

/* libtommath's layout, which the port fingerprints (looksLikeKeyMpInt reads
 * used/alloc/sign as the first three ints and the digit pointer at offset
 * 12). Getting this wrong makes every argument fail the mp_int shape check,
 * and sub-stage 4 then returns silently with callCount still 0 -- which is
 * indistinguishable from "the hook never fired". */
typedef struct {
    int used;
    int alloc;
    int sign;
    unsigned char *dp;
} mp_int;

static unsigned char g_mp_a[64], g_mp_b[64], g_mp_c[64];

/* The RSA output buffer. Stage 2 keys on a 2-byte read of dec_lic + 0x33, so
 * this has to be a real byte buffer; the mp_int that mp_exptmod writes
 * through sits at its start, which makes mp_exptmod's destination argument
 * and dec_lic the same address (that is how the port obtains dec_lic).
 *
 * Heap-allocated on purpose. A static buffer lives in .data, whose page is
 * full of other globals the program touches constantly: guarding it made
 * Stage 2's sub-stage 1 hit the re-arm cap (20001 hits) without ever seeing
 * the hash_3 read. The real dec_lic is an allocation, and its page is quiet. */
static unsigned char *g_dec_lic;

/* Stands in for libtomcrypt's mp_exptmod. The port only needs its address,
 * but it must be a real direct call for the E8 scan to find it. */
static NOINLINE int mp_exptmod(mp_int *G, mp_int *X, mp_int *P, mp_int *Y) {
    int i;
    int n = X->used < 64 ? X->used : 64;
    (void)P;
    for (i = 0; i < n; i++) {
        Y->dp[i] = (unsigned char)(G->dp[i] ^ X->dp[i]);
    }
    Y->used = n;
    return 0;
}

/* The read of the encrypted license happens in here, exactly as it does
 * inside libtomcrypt's mp_read_unsigned_bin. */
static NOINLINE void mp_read_unsigned_bin(mp_int *a,
                                          const volatile unsigned char *b,
                                          int c) {
    int i;
    int n = c < 64 ? c : 64;
    for (i = 0; i < n; i++) {
        a->dp[i] = b[i];
    }
    a->used = n;
}

/* Reads a local key pointer twice, then makes the direct call to
 * mp_exptmod -- the shape sub-stages 3 and 4 look for. */
static volatile int g_rsa_sink;

static NOINLINE int rsa_exptmod(mp_int *G, mp_int *X, mp_int *P, mp_int *Y,
                                const volatile unsigned char *lic,
                                int lic_len) {
    mp_int *key_tmp = X;
    int seen = key_tmp->used + key_tmp->used;
    int r;
    mp_read_unsigned_bin(G, lic, lic_len);
    r = mp_exptmod(G, key_tmp, P, Y);
    /* Something has to follow the call. Without it the compiler turns it
     * into a tail jump (jmp, not e8), and sub-stage 4 -- which looks for the
     * first direct call in rsa_exptmod -- would find nothing. Verified with
     * objdump: the call becomes `jmp <mp_exptmod>` at -O2 otherwise. */
    g_rsa_sink = r;
    (void)seen;
    return r;
}

static void spike_sleep_ms(int ms) {
#if defined(_WIN32)
    Sleep((DWORD)ms);
#else
    usleep((useconds_t)(ms * 1000));
#endif
}

/* Stage 2 looks for exactly 'cmp word ptr [reg1], reg2' (whatlicense's
 * isWordPtrRegCmp). A plain C comparison does not reliably produce it: GCC at
 * -O2 folded it to 'cmp $0xbeef,%ax', an immediate, which the port would never
 * match. Force the memory operand where inline asm is available; MSVC x64 has
 * no inline asm, so that build keeps the plain comparison as a best effort. */
static int spike_hash3_equal(volatile unsigned short *p,
                             unsigned short expected) {
#if defined(_MSC_VER) && defined(_M_IX86)
    int result;
    __asm {
        mov eax, p
        mov cx, expected
        cmp word ptr [eax], cx
        sete al
        movzx eax, al
        mov result, eax
    }
    return result;
#elif defined(__GNUC__)
    unsigned char equal;
    __asm__ volatile("cmpw %2, (%1)\n\tsete %0"
                     : "=q"(equal)
                     : "r"(p), "r"(expected)
                     : "cc", "memory");
    return (int)equal;
#else
    return *p == expected;
#endif
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

int main(int argc, char **argv) {
    const char *path = (argc > 1) ? argv[1] : "regkey.dat";
    unsigned char *src = NULL;
    unsigned char *dst = NULL;
    unsigned char head[8];
    size_t size = 0;
    size_t i;

    memset(head, 0, sizeof(head));
    printf("SPIKE2_TARGET bits=%d path=%s\n", (int)(sizeof(void *) * 8), path);
    fflush(stdout);
    wait_for_file("spike_go");

#if defined(_WIN32)
    {
        HANDLE file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        LARGE_INTEGER file_size;
        HANDLE mapping;
        if (file == INVALID_HANDLE_VALUE) {
            printf("SPIKE2_FAIL open err=%lu\n", (unsigned long)GetLastError());
            fflush(stdout);
            return 1;
        }
        if (!GetFileSizeEx(file, &file_size)) {
            printf("SPIKE2_FAIL size\n");
            fflush(stdout);
            return 1;
        }
        size = (size_t)file_size.QuadPart;
        mapping = CreateFileMappingA(file, NULL, PAGE_READONLY, 0, 0, NULL);
        if (mapping == NULL) {
            printf("SPIKE2_FAIL mapping\n");
            fflush(stdout);
            return 1;
        }
        src = (unsigned char *)MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
        if (src == NULL) {
            printf("SPIKE2_FAIL mapview\n");
            fflush(stdout);
            return 1;
        }
        if (size > 8) {
            memcpy(head, src, 8);
        }
        dst = (unsigned char *)malloc(size ? size : 1);
        for (i = 0; i < size; i++) {
            ((volatile unsigned char *)dst)[i] =
                ((volatile unsigned char *)src)[i];
        }
        UnmapViewOfFile(src);
        CloseHandle(mapping);
        CloseHandle(file);
    }
#else
    {
        int fd = open(path, O_RDONLY);
        struct stat st;
        if (fd < 0) {
            printf("SPIKE2_FAIL open\n");
            fflush(stdout);
            return 1;
        }
        if (fstat(fd, &st) != 0) {
            printf("SPIKE2_FAIL stat\n");
            fflush(stdout);
            return 1;
        }
        size = (size_t)st.st_size;
        src = (unsigned char *)mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (src == MAP_FAILED) {
            printf("SPIKE2_FAIL mmap\n");
            fflush(stdout);
            return 1;
        }
        if (size > 8) {
            memcpy(head, src, 8);
        }
        dst = (unsigned char *)malloc(size ? size : 1);
        for (i = 0; i < size; i++) {
            ((volatile unsigned char *)dst)[i] =
                ((volatile unsigned char *)src)[i];
        }
        munmap(src, size);
        close(fd);
    }
#endif

    /* Stage 1 needs a read of the license copy, and it has to happen inside
     * the RSA chain so sub-stages 2-5 have something to walk: the read is in
     * mp_read_unsigned_bin, called from rsa_exptmod, which then makes the
     * direct call to mp_exptmod. */
    {
        mp_int g, x, p;
        mp_int *y;
        int block;
        int blocks;
        g_dec_lic = (unsigned char *)calloc(4096, 1);
        if (g_dec_lic == NULL) {
            printf("SPIKE2_FAIL dec_lic alloc\n");
            fflush(stdout);
            return 1;
        }
        y = (mp_int *)g_dec_lic;
        /* used = 1 on purpose. The port fingerprints each argument as an
         * mp_int whose digit count is one of the RSA component lengths from
         * regkey.rsa -- and both exponents are 1 digit in the wl-lic dummy
         * keys (exp1Len = exp2Len = 1 on both arches), so 1 always matches
         * without hardcoding the modulus length, which differs per arch
         * (mod1Len 74 on x86, 35 on x64). */
        g.dp = g_mp_a; g.used = 1; g.alloc = 64; g.sign = 0;
        x.dp = g_mp_b; x.used = 1; x.alloc = 64; x.sign = 0;
        p.dp = g_mp_c; p.used = 1; p.alloc = 64; p.sign = 0;
        y->dp = g_dec_lic; y->used = 1; y->alloc = 4096; y->sign = 0;
        /* The real protection decrypts the license in dec_sections blocks
         * (lic_size / 0x80), so mp_exptmod is called that many times. This
         * matters for the port: it installs its hooks from a deferred
         * callback, i.e. after the first call has already returned, so a
         * single call is always missed and sub-stage 4 never completes. The
         * pause between blocks gives the agent time to arm. */
        /* dec_sections blocks are decrypted with the swapped-in key, and then
         * the protection verifies the signature with its own key. The port
         * completes -- restoring key1 and setting stage1Complete -- on the
         * call AFTER dec_sections.
         *
         * Run two extra blocks rather than one. Unlike PIN, which
         * instruments every instruction from the start, this port installs
         * its mp_exptmod hook at runtime from a deferred callback, so it can
         * miss call #1 (x64 did: 32 observed calls and no completion, while
         * x86 won the race and saw all 33). The extra block keeps the
         * completion transition reachable either way. */
        blocks = (int)(size / 0x80) + 2;
        for (block = 0; block < blocks; block++) {
            rsa_exptmod(&g, &x, &p, y,
                        (const volatile unsigned char *)dst, (int)size);
            printf("SPIKE2_RSA block=%d used=%d\n", block, y->used);
            fflush(stdout);
            spike_sleep_ms(20);
        }
    }

    /* Stage 2's target: hash_3 lives at dec_lic + 0x33, is read as a word, and
     * is then compared with 'cmp word ptr [reg1], reg2'.
     *
     * The read and the comparison are deliberately separated. Forcing the
     * memory operand with inline asm makes 'cmp word ptr [dec_lic+0x33], reg'
     * a single instruction that both reads and compares -- so the guard page
     * and the comparison land on the same instruction, Stage 2's Stalker
     * window opens too late, and nothing is ever found. whatlicense notes the
     * real code reads the value and then shuffles it through push/pop before
     * comparing, so the comparison must read a copy. */
    {
        volatile unsigned short *hash3 =
            (volatile unsigned short *)(g_dec_lic + 0x33);
        unsigned short observed = *hash3;
        unsigned short expected = 0xbeef;
        *hash3 = (unsigned short)(dst[0x33] | ((unsigned)dst[0x34] << 8));
        observed = *hash3;
        printf("SPIKE2_HASH3 ours=0x%04x expected=0x%04x\n",
               (unsigned)observed, (unsigned)expected);
        fflush(stdout);
        /* Give Stage 2's Stalker window time to open before comparing. */
        spike_sleep_ms(400);
        if (spike_hash3_equal(&observed, expected)) {
            printf("SPIKE2_HASH3 match\n");
        } else {
            printf("SPIKE2_HASH3 mismatch\n");
        }
        fflush(stdout);
    }

    printf("SPIKE2_DONE size=%lu head=%02x%02x%02x%02x%02x%02x%02x%02x "
           "copy=%02x%02x%02x%02x%02x%02x%02x%02x\n",
           (unsigned long)size,
           head[0], head[1], head[2], head[3], head[4], head[5], head[6],
           head[7],
           dst[0], dst[1], dst[2], dst[3], dst[4], dst[5], dst[6], dst[7]);
    fflush(stdout);

    /* Hold the process open so the agent can report against a live process. */
    wait_for_file("spike_exit");
    return 0;
}
