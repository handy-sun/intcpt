/* #define _POSIX_C_SOURCE 199309L */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/user.h>

#define LONG_SIZE (sizeof(long))

/* volatile sig_atomic_t g_sig_stat; */

char g_proc_maps[512] = { 0 };
char g_proc_exe[512] = { 0 };
char g_abs_exe[512] = { 0 };


typedef struct pack_total9
{
    uint32_t key;
    uint8_t  u8_1;
    uint8_t  u8_2;
    uint8_t  u8_3;
    uint8_t  u8_4;
    uint8_t  u8_5;
} __attribute__((packed)) PackTot;

const char *get_tm_timeval()
{
    static char s_time_chs[84];
    memset(s_time_chs, 0, sizeof(s_time_chs));
    struct timeval tv_cur = {};
    gettimeofday(&tv_cur, NULL);
    struct tm *t = localtime(&tv_cur.tv_sec);
    snprintf(s_time_chs, sizeof(s_time_chs) - 1, "%02d%02d %02d:%02d:%02d.%06ld",
        t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, tv_cur.tv_usec);
    return s_time_chs;
}

int wait4stop(pid_t pid) {
    int status = 0;
    do {
        if (waitpid(pid, &status, 0) == -1 || WIFEXITED(status) || WIFSIGNALED(status))
            return 0;
    } while (!WIFSTOPPED(status));
    return 1;
}

void handle_signal(int signal) {
    /* g_sig_stat = signal; */
    fprintf(stdout, "\nreceived: %d\n", signal);
    exit(EXIT_SUCCESS);
}

uint64_t get_base_addr(pid_t pid)
{
    const int BUFSIZE = 1024;

    if (snprintf(g_proc_maps, sizeof(g_proc_maps), "/proc/%d/maps", pid) <= 0) {
        perror("get proc_maps");
        return 0;
    }

    // read /proc/pid/exe
    if (snprintf(g_proc_exe, sizeof(g_proc_exe), "/proc/%d/exe", pid) <= 0) {
        perror("get proc_exe");
        return 0;
    }

    FILE *fp = fopen(g_proc_maps, "rb");
    if (!fp) {
        perror("open /proc/.. file err");
        exit(0);
    }

    int target_len = readlink(g_proc_exe, g_abs_exe, 100);
    /* target[target_len] = 0; */

    char buf[1024] = { 0 };
    char* pro_addr = buf;
    char* pro_maps = buf + 100;
    char* pro_name = pro_maps + 100;
    char* p = pro_name + 256;

    char data[512] = { 0 };
    while (!feof(fp)) {
        if (fgets(data, sizeof(data), fp) == NULL) {
            return 0;
        }

        sscanf(data, "%[^ ] %[^ ] %[^ ] %[^ ] %[^ ] %[^ ]", pro_addr, p, pro_maps, p, p, pro_name);
        if (memcmp(pro_name, g_abs_exe, target_len - 1) == 0 && memcmp(pro_maps, "00000000", 8) == 0) {
            fclose(fp);
            memset(p, 0, 10);
            sscanf(pro_addr, "%[^-]", p);
            uint64_t num = 0;
            sscanf(p, "%lx", &num);
            return num;
        }
        memset(data, 0, sizeof(data));
    }

    printf("not find addr\n");
    fclose(fp);

    return 0;
}


int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Target pid or keyword of process not input\n");
        return 1;
    }

    signal(SIGINT, handle_signal);

    /* fprintf(stdout, "sighandler: %d, my pid: %d\n", g_sig_stat, getpid()); */
    char *end_ptr = NULL;
    pid_t pid = (pid_t)strtol(argv[1], &end_ptr, 10);
    if (0 == pid) {
        perror("strtol failed");
        fprintf(stderr, "target pid is illegal\n");
        return 1;
    }

    fprintf(stdout, "traced pid: %d\n", pid);

    uint64_t base_addr = get_base_addr(pid);
    fprintf(stdout, "base addr: %#lx\n", base_addr);

    char cmd[512] = { 0 };
    snprintf(cmd, sizeof(cmd), "readelf -s %s -W | grep -i %s | awk '{print$2\" \" $3}'", g_abs_exe, argv[2]);
    FILE *pfp = popen(cmd, "r");
    if (pfp == NULL) {
        perror(cmd);
        return 1;
    }
    char tempBuff[256] = { 0 }; // save to buf
    if (fgets(tempBuff, sizeof(tempBuff), pfp) == NULL) {
        perror("fgets");
        pclose(pfp);
        return 1;
    }
    pclose(pfp);

    uint64_t offset_addr;
    uint32_t var_size;
    sscanf(tempBuff, "%lx %x", &offset_addr, &var_size);
    printf("offset_addr: %016lx %x\n", offset_addr, var_size);

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    long intercept = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    if (0 != intercept) {
        perror("ptrace attach failed");
        fprintf(stderr, "attach_ret: %ld\n", intercept);
        return 1;
    }

    if (!wait4stop(pid)) {
        perror("wait SIGSTOP of ptrace failed");
        return 1;
    }

    /* uint64_t addr = strtoull(argv[2], & nd_ptr, 10); */
    uint64_t addr = base_addr + offset_addr;
    printf("addr: %lu\n", addr);
    long peek_arr[9] = {};
    int i = 0;
    for (; i < sizeof(peek_arr) / sizeof(peek_arr[0]); ++i) {
        long peek_word = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
        if (errno != 0) {
            perror("peekdata error");
            return 2;
        }
        peek_arr[i] = peek_word;
        addr += LONG_SIZE;
    }

    long cont_ret = ptrace(PTRACE_DETACH, pid, NULL, NULL);
    if (errno != 0) {
        perror("PTRACE_DETACH failed");
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    double elapsed = (end.tv_nsec - start.tv_nsec) / 1000.0;
    fprintf(stdout, "end: [%s]\n", get_tm_timeval() + 5);
    fprintf(stdout, "elapsed: %02ld_%010.3f,\n", end.tv_sec - start.tv_sec, elapsed);

    uint8_t *buf = (uint8_t *)peek_arr;
    int off = 0;
    for (; off + sizeof(PackTot) <= sizeof(peek_arr); off += sizeof(PackTot)) {
        PackTot pt = *(PackTot *)(buf + off);
        fprintf(stdout, "PackTot{ key: %u, [ %u, %u, %u, %u, %u ] }\n",
                pt.key, pt.u8_1, pt.u8_2, pt.u8_3, pt.u8_4, pt.u8_5);
    }

    return 0;
}

