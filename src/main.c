/* #define _POSIX_C_SOURCE 199309L */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <stdbool.h>
#include <limits.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/user.h>


#define INIT_ZERO { 0 }

#define OUT_VAR(var, format) fprintf(stdout, #var ":[%" #format "] ", var)

#define ERR_VAR(var, format) fprintf(stderr, #var ":[%" #format "] ", var)

#define SAFE_FREE(x) if (x) { free(x); x=NULL; }

#define SAFE_PCLOSE(x) if (x) { pclose(x); x=NULL; }


/* /proc/<pid>/maps */
char g_proc_maps[NAME_MAX + 16];
/* /proc/<pid>/exe */
char g_proc_exe[NAME_MAX + 16];
/* readlink -f /proc/<pid>/exe */
char g_exe_link[NAME_MAX];

#pragma pack(push)
#pragma pack(1)
typedef struct pack_total9 {
    uint32_t key;
    uint8_t  u8_1;
    uint8_t  u8_2;
    uint8_t  u8_3;
    uint8_t  u8_4;
    uint8_t  u8_5;
} PackTot;
#pragma pack(pop)

const char *get_tm_timeval() {
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

uint64_t get_base_addr(pid_t pid) {
    if (snprintf(g_proc_maps, sizeof(g_proc_maps), "/proc/%d/maps", pid) <= 0) {
        perror("get proc_maps");
        return 0;
    }

    if (snprintf(g_proc_exe, sizeof(g_proc_exe), "/proc/%d/exe", pid) <= 0) {
        perror("get proc_exe");
        return 0;
    }

    FILE *fp = fopen(g_proc_maps, "rb");
    if (!fp) {
        perror("open /proc/.. file err");
        return 0;
    }

    // get symbol link /proc/<pid>/exe
    ssize_t target_len = readlink(g_proc_exe, g_exe_link, sizeof(g_exe_link));
    if (-1 == target_len || target_len == sizeof(g_exe_link)) {
        perror("readlink");
        return 0;
    }

    char buf[1024] = INIT_ZERO;
    char *pro_addr = buf;
    char *pro_maps = buf + 100;
    char *pro_name = pro_maps + 100;
    char *p = pro_name + 256;

    char data[256] = INIT_ZERO;
    do {
        if (fgets(data, sizeof(data), fp) == NULL) {
            if (errno != 0) {
                perror("fgets");
            } else {
                fprintf(stderr, "fgets(): may reached the EOF\n");
            }
            break;
        }

        sscanf(data, "%[^ ] %[^ ] %[^ ] %[^ ] %[^ ] %[^ ]", pro_addr, p, pro_maps, p, p, pro_name);
        if (memcmp(pro_name, g_exe_link, target_len - 1) == 0 && memcmp(pro_maps, "00000000", 8) == 0) {
            fclose(fp);
            memset(p, 0, 10);
            sscanf(pro_addr, "%[^-]", p);
            uint64_t num = 0;
            sscanf(p, "%lx", &num);
            return num;
        }
        memset(data, 0, sizeof(data));
        memset(buf, 0, sizeof(buf));
    } while (!feof(fp));

    printf("not find addr\n");
    fclose(fp);

    return 0;
}

_Bool get_var_addr_size(const char *var_name, uint64_t *p_addr, uint32_t *p_size) {
    char cmd[NAME_MAX + 97] = INIT_ZERO;
    snprintf(cmd, sizeof(cmd), "readelf -s %s -W | grep %s", g_exe_link, var_name);
    FILE *pipe_fp = popen(cmd, "r");
    if (pipe_fp == NULL) {
        perror(cmd);
        SAFE_PCLOSE(pipe_fp);
        return false;
    }

    char oneline[256] = INIT_ZERO;
    char buffs[1024] = INIT_ZERO;
    char *num  = buffs;
    char *type = num + 16;
    char *bind = type + 16;
    char *vis  = bind + 16;
    char *ndx  = vis + 16;
    char *name = ndx + 16;

    do {
        if (fgets(oneline, sizeof(oneline), pipe_fp) == NULL) {
            if (errno != 0) {
                perror("fgets");
            } else {
                fprintf(stderr, "fgets(): may reached the EOF\n");
            }
            break;
        }

        OUT_VAR(oneline, s);
        printf("\n");
        if (-1 == sscanf(oneline, "%s %lx %u %s %s %s %s %s",
                         num, p_addr, p_size, type, bind, vis, ndx, name)) {
            perror("sscanf");
            break;
        }

        /* if (memcmp(type, "OBJECT", 6) == 0 && memcmp(bind, "GLOBAL", 6) == 0) { */
        if (strcmp(type, "OBJECT") == 0 && strcmp(bind, "GLOBAL") == 0) {
            OUT_VAR(name, s);
            printf("\n");
            break;
        } else {
            OUT_VAR(type, s);OUT_VAR(bind, s);
            printf("\n");
        }

        memset(oneline, 0, sizeof(oneline));
        memset(buffs, 0, sizeof(buffs));
    } while (!feof(pipe_fp));
    SAFE_PCLOSE(pipe_fp);

    if (0 == *p_addr || 0 == *p_size) {
        ERR_VAR(*p_addr, lu);
        ERR_VAR(*p_size, u);
        fprintf(stderr, "\n");
        return false;
    }

    return true;
}


int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Target pid or keyword of process not input\n");
        return 1;
    }

    char *end_ptr = NULL;
    const pid_t pid = (pid_t)strtol(argv[1], &end_ptr, 10);
    if (0 == pid) {
        perror("strtol failed");
        fprintf(stderr, "target pid is illegal\n");
        return 1;
    }

    fprintf(stdout, "traced pid: %d\n", pid);

    const uint64_t base_addr = get_base_addr(pid);
    fprintf(stdout, "base addr: 0x%016lx\n", base_addr);
    if (0 == base_addr) {
        return 1;
    }

    uint64_t offset_addr = 0;
    uint32_t sz = 0;
    if (!get_var_addr_size(argv[2], &offset_addr, &sz)) {
        return 1;
    }
    fprintf(stdout, "offset_addr: %#lx, size: %u\n", offset_addr, sz);

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

    const uint64_t var_addr = base_addr + offset_addr;
    printf("addr: %lu (0x%016lx)\n", var_addr, var_addr);

    uint8_t *peek_arr = (uint8_t *)calloc(sizeof(uint8_t), sz);

    int i = 0;
    while (i < sz) {
        if (i + sizeof(long) > sz) {
            printf("before i: %d, ", i);
            i = sz - sizeof(long);
            printf("now i: %d\n", i);
        }
        long peek_word = ptrace(PTRACE_PEEKDATA, pid, var_addr + i, NULL);
        if (errno != 0) {
            perror("peekdata error");
            return 2;
        }
        memcpy(peek_arr + i, &peek_word, sizeof(long));
        i += sizeof(long);
    }

    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    if (errno != 0) {
        perror("PTRACE_DETACH failed");
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    const double elapsed = (end.tv_nsec - start.tv_nsec) / 1000.0;
    fprintf(stdout, "end: [%s]\n", get_tm_timeval() + 5);
    fprintf(stdout, "trace total elapsed: %02lds %010.3fus,\n", end.tv_sec - start.tv_sec, elapsed);

    const uint8_t *buf = (uint8_t *)peek_arr;
    int off = 0;
    for (; off + sizeof(PackTot) <= sz; off += sizeof(PackTot)) {
        PackTot pt = *(PackTot *)(buf + off);
        fprintf(stdout, "key: %4u, [ %3u, %3u, %3u, %3u, %3u ]\n",
                pt.key, pt.u8_1, pt.u8_2, pt.u8_3, pt.u8_4, pt.u8_5);
    }
    SAFE_FREE(peek_arr);

    return 0;
}

