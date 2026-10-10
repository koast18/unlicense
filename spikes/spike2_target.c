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
