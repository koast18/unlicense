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

typedef struct {
    unsigned char *dp;
    int used;
} mp_int;

static unsigned char g_mp_a[64], g_mp_b[64], g_mp_c[64], g_mp_d[64];

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
        mp_int g, x, p, y;
        g.dp = g_mp_a; g.used = 0;
        x.dp = g_mp_b; x.used = 4;
        p.dp = g_mp_c; p.used = 4;
        y.dp = g_mp_d; y.used = 0;
        rsa_exptmod(&g, &x, &p, &y, (const volatile unsigned char *)dst,
                    (int)size);
        printf("SPIKE2_RSA used=%d\n", y.used);
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
