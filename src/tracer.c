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
    char buf[1024] = { 0 };
    char* pro_maps_path = buf;

    // open /proc/pid/maps
    pro_maps_path += sprintf(pro_maps_path, "%s", "/proc/");
    pro_maps_path += sprintf(pro_maps_path, "%d", pid);
    sprintf(pro_maps_path, "/%s", "maps");
    FILE *fp = fopen(buf, "rb");
    if (!fp)
    {
        perror("open /proc/.. file err");
        exit(0);
    }

    // read /proc/pid/exe
    memset(buf, 0, BUFSIZE);
    char* pro_exe_path = buf;
    pro_exe_path += sprintf(pro_exe_path, "%s", "/proc");
    pro_exe_path += sprintf(pro_exe_path, "/%d", pid);
    sprintf(pro_exe_path, "/%s", "exe");
    char target[100] = { 0 };
    int target_len = readlink(buf, target, 100);
    /* target[target_len] = 0; */
    printf("proc exe: %s\n", target);

    char cmd[1024] = { 0 };
    snprintf(cmd, sizeof(cmd), "objdump -d -j .bss %s | grep -i pcmstate | awk '{print$1}'", target);
    FILE *pfp = popen(cmd, "r");
    if (pfp == NULL)
    {
        perror(cmd);
        return 1;
    }
    char tempBuff[64]; // save to buf
    if (fgets(tempBuff, 64, pfp) == NULL)
    {
        perror("fgets");
        pclose(pfp);
        return 1;
    }
    pclose(pfp);
    uint64_t offset_addr;
    sscanf(tempBuff, "%lx", &offset_addr);
    printf("offset_addr: %#lx\n", offset_addr);

    memset(buf, 0, BUFSIZE);
    char* pro_addr = buf;
    char* pro_maps = buf + 100;
    char* pro_name = pro_maps + 100;
    char* p = pro_name + 256;

    char data[512] = { 0 };
    while (!feof(fp))
    {
        if (fgets(data, sizeof(data), fp) == NULL)
            return 0;

        sscanf(data, "%[^ ] %[^ ] %[^ ] %[^ ] %[^ ] %[^ ]", pro_addr, p, pro_maps, p, p, pro_name);
        // printf("pro_addr %s pro_maps %s pro_name %s --> %d %d\n",pro_addr,pro_maps,pro_name,memcmp(pro_name,target,target_len-1),memcmp(pro_maps,"00000000",8));
        if (memcmp(pro_name, target, target_len - 1) == 0 && memcmp(pro_maps, "00000000", 8) == 0)
        {
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
        fprintf(stderr, "Target pid or addr of process not input\n");
        return 1;
    }

    signal(SIGINT, handle_signal);

    /* fprintf(stdout, "sighandler: %d, my pid: %d\n", g_sig_stat, getpid()); */
    fprintf(stdout, "my pid: %d\n", getpid());
    char *end_ptr = NULL;
    pid_t pid = (pid_t)strtol(argv[1], &end_ptr, 10);

    if (0 == pid) {
        perror("strtol failed");
        fprintf(stderr, "target pid is illegal\n");
        return 1;
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    uint64_t base = get_base_addr(pid);
    fprintf(stdout, "base addr: %#lx\n", base);

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

    uint64_t addr = strtoull(argv[2], &end_ptr, 10);
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

