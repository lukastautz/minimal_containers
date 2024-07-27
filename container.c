#ifdef __dietlibc__
#define _GNU_SOURCE /* for u_intN_t + sched.h */
#include <sched.h>
#else
#include <linux/sched.h>
#include <features.h>
#ifdef __GLIBC__
#include <sys/sysmacros.h>
#define O_PATH         01000000
#define AT_EMPTY_PATH  0x1000
int execveat(int, char *, const char **, const char **, int);
int unshare(int);
#endif
#endif

#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <signal.h>
#include <sys/wait.h>
#include <dirent.h>

#include "config.h"

typedef u_int8_t   uint8;
typedef u_int16_t  uint16;
typedef u_int32_t  uint32;
typedef u_int64_t  uint64;
typedef int8_t     int8;
typedef int16_t    int16;
typedef int32_t    int32;
typedef int64_t    int64;
typedef u_int8_t   bool;

#define true 1
#define false 0

#define STDOUT 1
#define STDERR 2

#define SLEN(s) s, strlen(s)
#define SBLEN(s) s, sizeof(s)
#define write_const_stdout(s)   write(STDOUT, s, strlen(s))
#define write_const_stderr(s)   write(STDERR, s, strlen(s))

#define CLONE_NEWTIME 0x00000080

char *get_shell(void) {
    char *ret = getenv("SHELL");
    if (ret)
        return ret;
    return DEFAULT_SHELL;
}

#define write_const_fd(fd, s) write(fd, SLEN(s))
#define log(s) write_const_fd(log_fd, s "\n")
#define error(s) \
    { \
        log("Error: " s); \
        quit(); \
    }

#define LINKED_LIST(name, data) \
    typedef struct name { \
        struct name *next; \
        struct name *last; \
        data \
    } name;

LINKED_LIST(bind_mount, \
            char source[128]; \
            char target[128]; \
            bool read_only; \
           )

LINKED_LIST(io_limit, \
            char data[32]; \
            uint8 len; \
           )

struct {
    char max_physical_memory[16]; // not zero-terminated
    char max_memory[16];          // not zero-terminated
    char cpu_share[8];            // not zero-terminated
    char net_classid[16];         // not zero-terminated
    char init[128];               // zero-terminated
    char root[128];               // zero-terminated
    uint8 max_physical_memory_len;
    uint8 max_memory_len;
    uint8 cpu_share_len;
    uint8 net_classid_len;
    uint8 root_len;
    bind_mount *mounts;
    io_limit *iops_limits;
    io_limit *io_bw_limits;
    int32 namespaces;
} config;

char buf[MAX_CONFIG_LENGTH];

int log_fd = 2;

void quit(void) {
    close(log_fd);
    exit(1);
}

int _open(char *name, int mode) {
    int fd = open(name, mode);
    if (fd == -1)
        error("Opening file failed!");
    return fd;
}

void add_custom_mount(char *data, uint8 len, bool read_only) {
    char *sep = strchr(data, ':');
    if (!sep)
        error("invalid mount!");
    uint8 source_len = sep - data, target_len = len - source_len - 2;
    /* target is without preceding '/' because mount will be relative from root directory */
    if ((source_len + 1) > sizeof(((bind_mount *)0)->source) || (target_len + 1) > sizeof(((bind_mount *)0)->target))
        error("too big!");
    bind_mount *ptr = malloc(sizeof(bind_mount)), *pos = config.mounts;
    if (!ptr)
        error("malloc failed!");
    ptr->next = NULL;
    if (pos) {
        while (pos->next)
            pos = pos->next;
        pos->next = ptr;
        ptr->last = pos;
    } else {
        config.mounts = ptr;
        ptr->last = NULL;
    }
    memcpy(ptr->source, data, source_len);
    memcpy(ptr->target, sep + 2, target_len);
    ptr->source[source_len] = ptr->target[target_len] = '\0';
    ptr->read_only = read_only;
}

void add_io_limit(char *data, uint8 len, io_limit **dest) {
    io_limit *ptr = malloc(sizeof(io_limit)), *pos = *dest;
    if (!ptr)
        error("malloc failed!");
    ptr->next = NULL;
    if (pos) {
        while (pos->next)
            pos = pos->next;
        pos->next = ptr;
        ptr->last = pos;
    } else {
        *dest = ptr;
        ptr->last = NULL;
    }
    memcpy(ptr->data, data, len);
    ptr->len = len;
}

#define DOUBLE_KEY_CHECK(key) \
    { \
        if (config.key[0]) \
            error("Double key " #key "!"); \
    }

#define CONFIG_COPY_SET_LEN(key) \
    { \
        if (sizeof(config.key) >= val_len) { \
            memcpy(config.key, ptr_after_equals_sign, val_len); \
            config.key##_len = val_len; \
        } else \
            error("Value too long!"); \
    }

#define EQUALS_CONST(a, const_b) !memcmp(a, const_b, sizeof(const_b))

void parse_config(int fd) {
    memset(&config, 0, sizeof(config));
    uint16 len, pos = 0, val_len;
    char *ptr_start_of_line = buf, *ptr_after_equals_sign, *tmp = buf;
    while ((len = read(fd, tmp, 1024)) > 0)
        tmp += len;
    close(fd);
    if ((len = tmp - buf) < sizeof("init=\nroot="))
        error("config is too short!");
    enum {
        none = 0,
        init,
        root,
        namespaces,
        max_physical_memory,
        max_memory,
        cpu_share,
        net_classid,
        mount,
        mount_ro,
        iops_limit,
        io_bw_limit
    } key = none;
    for (uint16 i = 0; i <= len; ++i) {
        if (i == len) {
            if (buf[i - 1] != '\n')
                buf[i] = '\n';
            else
                break;
        }
        switch (buf[i]) {
            case '\n':
                ptr_start_of_line = buf + i + 1; // next line
                if (key) {
                    val_len = buf + i - ptr_after_equals_sign;
                    switch (key) {
                        case init:
                            DOUBLE_KEY_CHECK(init);
                            if (sizeof(config.init) > val_len) {
                                memcpy(config.init, ptr_after_equals_sign, val_len);
                                config.init[val_len] = '\0';
                            } else
                                error("Value too long!");
                            break;
                        case root:
                            DOUBLE_KEY_CHECK(root);
                            if (sizeof(config.root) > val_len) {
                                memcpy(config.root, ptr_after_equals_sign, val_len);
                                config.root_len = val_len;
                                config.root[val_len] = '\0';
                            } else
                                error("Value too long!");
                            break;
                        case namespaces:
                            if (config.namespaces)
                                error("Double key namespaces!");
                            if (val_len > strlen("uphti"))
                                error("too long");
                            if (val_len == strlen("all") && !memcmp(ptr_after_equals_sign, SLEN("all"))) {
                                config.namespaces = CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWTIME | CLONE_NEWIPC;
                                break;
                            }
                            for (uint8 i = 0; i < val_len; ++i) {
                                switch (ptr_after_equals_sign[i]) {
                                    case 'u':
                                        config.namespaces |= CLONE_NEWUSER;
                                        break;
                                    case 'p':
                                        config.namespaces |= CLONE_NEWPID;
                                        break;
                                    case 'h':
                                        config.namespaces |= CLONE_NEWUTS;
                                        break;
                                    case 't':
                                        config.namespaces |= CLONE_NEWTIME;
                                        break;
                                    case 'i':
                                        config.namespaces |= CLONE_NEWIPC;
                                        break;
                                    default:
                                        error("unknown namespace");
                                }
                            }
                            break;
                        case max_physical_memory:
                            DOUBLE_KEY_CHECK(max_physical_memory);
                            CONFIG_COPY_SET_LEN(max_physical_memory);
                            break;
                        case max_memory:
                            DOUBLE_KEY_CHECK(max_memory);
                            CONFIG_COPY_SET_LEN(max_memory);
                            break;
                        case cpu_share:
                            DOUBLE_KEY_CHECK(cpu_share);
                            CONFIG_COPY_SET_LEN(cpu_share);
                            break;
                        case net_classid:
                            DOUBLE_KEY_CHECK(net_classid);
                            CONFIG_COPY_SET_LEN(net_classid);
                            break;
                        case mount:
                        case mount_ro:
                            if (val_len > 255)
                                error("too long");
                            add_custom_mount(ptr_after_equals_sign, val_len, key == mount_ro);
                            break;
                        case iops_limit:
                            if (val_len > sizeof(((io_limit *)0)->data))
                                error("too long");
                            add_io_limit(ptr_after_equals_sign, val_len, &config.iops_limits);
                            break;
                        case io_bw_limit:
                            if (val_len > sizeof(((io_limit *)0)->data))
                                error("too long");
                            add_io_limit(ptr_after_equals_sign, val_len, &config.io_bw_limits);
                            break;
                    }
                } else if (buf[i - 1] != '\n' && i != 0)
                    error("malformed config (unexpected newline)!");
                key = none;
                break;
            case '=':
                buf[i] = '\0';
                if (EQUALS_CONST(ptr_start_of_line, "init"))
                    key = init;
                else if (EQUALS_CONST(ptr_start_of_line, "root"))
                    key = root;
                else if (EQUALS_CONST(ptr_start_of_line, "namespaces"))
                    key = namespaces;
                else if (EQUALS_CONST(ptr_start_of_line, "max_physical_memory"))
                    key = max_physical_memory;
                else if (EQUALS_CONST(ptr_start_of_line, "max_memory"))
                    key = max_memory;
                else if (EQUALS_CONST(ptr_start_of_line, "cpu_share"))
                    key = cpu_share;
                else if (EQUALS_CONST(ptr_start_of_line, "net_classid"))
                    key = net_classid;
                else if (EQUALS_CONST(ptr_start_of_line, "mount"))
                    key = mount;
                else if (EQUALS_CONST(ptr_start_of_line, "mount_ro"))
                    key = mount_ro;
                else if (EQUALS_CONST(ptr_start_of_line, "iops_limit"))
                    key = iops_limit;
                else if (EQUALS_CONST(ptr_start_of_line, "io_bw_limit"))
                    key = io_bw_limit;
                else
                    error("malformed config (unknown key)!");
                ptr_after_equals_sign = buf + i + 1;
                break;
            case '#':
                if (key)
                    error("Unexpected '#'!") //;
                else {
                    while (buf[i++] != '\n');
                    ptr_start_of_line = buf + i;
                }
        }
    }
    if (!(config.root_len && *config.init && config.namespaces))
        error("Missing key(s)!");
}

void prepare_cgroups(char *name, uint8 len) {
    int fd;
    memcpy(buf, SLEN("/sys/fs/cgroup/devices/"));
    memcpy(buf + strlen("/sys/fs/cgroup/devices/"), name, len + 1);
    mkdir(buf, 0755);
    memcpy(buf + strlen("/sys/fs/cgroup/devices/") + len, SBLEN("/devices.deny"));
    write(fd = _open(buf, O_WRONLY), SLEN("b *:* rwm"));
    close(fd);
    if (config.max_memory_len || config.max_physical_memory_len) {
        memcpy(buf + strlen("/sys/fs/cgroup/"), SLEN("memory/"));
        memcpy(buf + strlen("/sys/fs/cgroup/memory/"), name, len + 1);
        mkdir(buf, 0755);
        if (config.max_memory_len) {
            memcpy(buf + strlen("/sys/fs/cgroup/memory/") + len, SBLEN("/memory.limit_in_bytes"));
            write(fd = _open(buf, O_WRONLY), config.max_physical_memory, config.max_physical_memory_len);
            close(fd);
        }
        if (config.max_physical_memory_len) {
            memcpy(buf + strlen("/sys/fs/cgroup/memory/") + len, SBLEN("/memory.memsw.limit_in_bytes"));
            write(fd = _open(buf, O_WRONLY), config.max_memory, config.max_memory_len);
            close(fd);
        }
    }
    if (config.cpu_share_len) {
        memcpy(buf + strlen("/sys/fs/cgroup/"), SLEN("cpu/"));
        memcpy(buf + strlen("/sys/fs/cgroup/cpu/"), name, len + 1);
        mkdir(buf, 0755);
        memcpy(buf + strlen("/sys/fs/cgroup/cpu/") + len, SBLEN("/cpu.shares"));
        write(fd = _open(buf, O_WRONLY), config.cpu_share, config.cpu_share_len);
        close(fd);
    }
    if (config.net_classid_len) {
        memcpy(buf + strlen("/sys/fs/cgroup/"), SLEN("net_cls/"));
        memcpy(buf + strlen("/sys/fs/cgroup/net_cls/"), name, len + 1);
        mkdir(buf, 0755);
        memcpy(buf + strlen("/sys/fs/cgroup/net_cls/") + len, SBLEN("/net_cls.classid"));
        write(fd = _open(buf, O_WRONLY), config.net_classid, config.net_classid_len);
        close(fd);
    }
    if (config.io_bw_limits || config.iops_limits) {
        memcpy(buf + strlen("/sys/fs/cgroup/"), SLEN("blkio/"));
        memcpy(buf + strlen("/sys/fs/cgroup/blkio/"), name, len + 1);
        mkdir(buf, 0755);
        memcpy(buf + strlen("/sys/fs/cgroup/blkio/") + len, SBLEN("/blkio.throttle."));
        io_limit *io_limit = config.iops_limits;
        while (io_limit) {
            memcpy(buf + strlen("/sys/fs/cgroup/blkio/") + len + strlen("/blkio.throttle."), SBLEN("read_iops_device"));
            write(fd = _open(buf, O_WRONLY), io_limit->data, io_limit->len);
            close(fd);
            memcpy(buf + strlen("/sys/fs/cgroup/blkio/") + len + strlen("/blkio.throttle."), SBLEN("write_iops_device"));
            write(fd = _open(buf, O_WRONLY), io_limit->data, io_limit->len);
            close(fd);
            io_limit = io_limit->next;
        }
        io_limit = config.io_bw_limits;
        while (io_limit) {
            memcpy(buf + strlen("/sys/fs/cgroup/blkio/") + len + strlen("/blkio.throttle."), SBLEN("read_bps_device"));
            write(fd = _open(buf, O_WRONLY), io_limit->data, io_limit->len);
            close(fd);
            memcpy(buf + strlen("/sys/fs/cgroup/blkio/") + len + strlen("/blkio.throttle."), SBLEN("write_bps_device"));
            write(fd = _open(buf, O_WRONLY), io_limit->data, io_limit->len);
            close(fd);
            io_limit = io_limit->next;
        }
    }
}

uint8 itoa(uint32 n, char *s) {
    uint8 i = 0, y = 0, z;
    do
        s[i] = n % 10 + '0', ++i;
    while ((n /= 10) > 0);
    z = i - 1;
    for (char c; y < z; ++y, --z)
        c = s[y], s[y] = s[z], s[z] = c;
    return i;
}

void save_pid(char *name, uint8 len) {
    memcpy(buf, SLEN(PATH "/pids/"));
    memcpy(buf + strlen(PATH "/pids/"), name, len + 1);
    int fd = _open(buf, O_WRONLY | O_CREAT | O_TRUNC);
    write(fd, buf, itoa(getpid(), buf));
    close(fd);
}

void start_cgroups(char *name, uint8 len) {
    char pidbuf[26];
    uint8 l;
    memcpy(buf, SLEN("/sys/fs/cgroup/devices/"));
    memcpy(buf + strlen("/sys/fs/cgroup/devices/"), name, len);
    memcpy(buf + strlen("/sys/fs/cgroup/devices/") + len, SBLEN("/cgroup.procs"));
    int fd = _open(buf, O_WRONLY);
    write(fd, pidbuf, l = itoa(getpid(), pidbuf));
    close(fd);
    if (config.cpu_share_len) {
        memcpy(buf + strlen("/sys/fs/cgroup/"), SLEN("cpu/"));
        memcpy(buf + strlen("/sys/fs/cgroup/cpu/"), name, len);
        memcpy(buf + strlen("/sys/fs/cgroup/cpu/") + len, SBLEN("/cgroup.procs"));
        write(fd = _open(buf, O_WRONLY), pidbuf, l);
        close(fd);
    }
    if (config.net_classid_len) {
        memcpy(buf + strlen("/sys/fs/cgroup/"), SLEN("net_cls/"));
        memcpy(buf + strlen("/sys/fs/cgroup/net_cls/"), name, len);
        memcpy(buf + strlen("/sys/fs/cgroup/net_cls/") + len, SBLEN("/cgroup.procs"));
        write(fd = _open(buf, O_WRONLY), pidbuf, l);
        close(fd);
    }
    if (config.max_memory_len || config.max_physical_memory_len) {
        memcpy(buf + strlen("/sys/fs/cgroup/"), SLEN("memory/"));
        memcpy(buf + strlen("/sys/fs/cgroup/memory/"), name, len);
        memcpy(buf + strlen("/sys/fs/cgroup/memory/") + len, SBLEN("/cgroup.procs"));
        write(fd = _open(buf, O_WRONLY), pidbuf, l);
        close(fd);
    }
    if (config.io_bw_limits || config.iops_limits) {
        memcpy(buf + strlen("/sys/fs/cgroup/"), SLEN("blkio/"));
        memcpy(buf + strlen("/sys/fs/cgroup/blkio/"), name, len);
        memcpy(buf + strlen("/sys/fs/cgroup/blkio/") + len, SBLEN("/cgroup.procs"));
        write(fd = _open(buf, O_WRONLY), pidbuf, l);
        close(fd);
    }
}

void rrm(char *dir_name, uint16 dir_len) {
    char buf[2048];
    memcpy(buf, dir_name, dir_len);
    buf[dir_len] = '/';
    struct stat element;
    DIR *dir;
    struct dirent *dir_entry;
    uint16 d_name_len;
    if (!(dir = opendir(dir_name)))
        error("opendir failed!");
    while (dir_entry = readdir(dir))
        if (memcmp(dir_entry->d_name, SBLEN(".")) && memcmp(dir_entry->d_name, SBLEN(".."))) {
            d_name_len = strlen(dir_entry->d_name);
            if (dir_len + d_name_len >= sizeof(buf))
                error("name too long");
            memcpy(buf + dir_len + 1, dir_entry->d_name, d_name_len + 1);
            lstat(buf, &element);
            if (S_ISDIR(element.st_mode)) {
                rrm(buf, dir_len + 1 + d_name_len);
                if (rmdir(buf) == -1)
                    error("rmdir failed");
            } else
                if (unlink(buf) == -1)
                    error("unlink failed");
        }
    closedir(dir);
}

void mount_dirs(void) {
    if (chdir(config.root) == -1)
        error("chdir failed!");
    struct stat element;
    if (!lstat("dev", &element)) {
        umount("dev/pts");
        rrm(SLEN("dev"));
        rmdir("dev");
    }
    if (!lstat("tmp", &element))
        rrm(SLEN("tmp"));
    else
        mkdir("tmp", 0777);
    if (
        mkdir("dev", 0655) == -1 ||
        mkdir("dev/pts", 0655) == -1 ||
        mkdir("dev/mqueue", 0777) == -1 ||
        mkdir("dev/shm", 0777) == -1 ||
        mknod("dev/null", S_IFCHR | 0666, makedev(1, 3)) == -1 ||
        mknod("dev/zero", S_IFCHR | 0666, makedev(1, 5)) == -1 ||
        mknod("dev/full", S_IFCHR | 0666, makedev(1, 7)) == -1 ||
        mknod("dev/random", S_IFCHR | 0444, makedev(1, 8)) == -1 ||
        mknod("dev/urandom", S_IFCHR | 0444, makedev(1, 9)) == -1 ||
        mknod("dev/ptmx", S_IFCHR | 0666, makedev(5, 2)) == -1 ||
        mknod("dev/vcs", S_IFCHR | 0660, makedev(7, 0)) == -1 ||
        mknod("dev/userfaultfd", S_IFCHR | 0600, makedev(10, 126)) == -1 ||
        mknod("dev/cuse", S_IFCHR | 0600, makedev(10, 203)) == -1 ||
        mknod("dev/hpet", S_IFCHR | 0600, makedev(10, 228)) == -1 ||
        mknod("dev/fuse", S_IFCHR | 0666, makedev(10, 229)) == -1 ||
        (!(config.namespaces & CLONE_NEWUSER) && mknod("dev/kvm", S_IFCHR | 0660, makedev(10, 232)) == -1) ||
        mknod("dev/ppp", S_IFCHR | 0600, makedev(108, 0)) == -1 ||
        mknod("dev/rtc0", S_IFCHR | 0444, makedev(251, 0)) == -1 ||
        symlink("/proc/self/fd", "dev/fd") == -1 ||
        symlink("/proc/self/fd/0", "dev/stdin") == -1 ||
        symlink("/proc/self/fd/1", "dev/stdout") == -1 ||
        symlink("/proc/self/fd/2", "dev/stderr") == -1 ||
        symlink("/dev/rtc0", "dev/rtc") == -1 ||
        mount("none", "dev/pts", "devpts", MS_NOEXEC | MS_NOSUID, NULL) == -1
    )
        error("Failed to prepare /dev!");
    if (!(config.namespaces & CLONE_NEWPID) && mount("proc", "proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) == -1)
        error("mount(/proc) failed!");
    bind_mount *mnt = config.mounts;
    while (mnt) {
        if (lstat(mnt->target, &element)) {
            if (lstat(mnt->source, &element))
                error("source doesn't exist");
            if (S_ISDIR(element.st_mode))
                mkdir(mnt->target, 0777);
            else
                close(open(mnt->target, O_CREAT | O_WRONLY, 0777));
        }
        umount(mnt->target);
        if (mount(mnt->source, mnt->target, "", MS_BIND, NULL) == -1)
            log("mount error occurred..."); // nonfatal?
        if (mnt->read_only && mount(mnt->source, mnt->target, "", MS_BIND | MS_REMOUNT | MS_RDONLY, NULL) == -1)
            error("remounting read-only failed!");
        mnt = mnt->next;
    }
}

void free_mounts(void) {
    bind_mount *mnt = config.mounts, *tmp;
    while (mnt->next)
        mnt = mnt->next;
    while (mnt) {
        tmp = mnt->last;
        free(mnt);
        mnt = tmp;
    }
}

void free_io_limit(io_limit **limit) {
    io_limit *tmp;
    while ((*limit)->next)
        *limit = (*limit)->next;
    while (*limit) {
        tmp = (*limit)->last;
        free(*limit);
        *limit = tmp;
    }
}

void free_linked_lists(void) {
    if (config.mounts)
        free_mounts();
    if (config.iops_limits)
        free_io_limit(&config.iops_limits);
    if (config.io_bw_limits)
        free_io_limit(&config.io_bw_limits);
}

void kill_if_running(char *name, uint8 len) {
    memcpy(buf, SLEN(PATH "/pids/"));
    memcpy(buf + strlen(PATH "/pids/"), name, len + 1);
    int fd = open(buf, O_RDONLY);
    if (fd == -1)
        return;
    if ((len = read(fd, buf, 64)) < 1)
        error("read() failed!\n");
    close(fd);
    buf[len] = '\0';
    kill(atoi(buf), 9);
}

void do_nothing(int) { }

void help_start(void) {
    write_const_stderr("Usage: container start [-d|-s] {CONTAINER}\nOptions:\n\t-d\tDon't detach from terminal.\n\t-s\tStart (interactively) the shell (either environment SHELL, or /bin/bash)\n");
    exit(0);
}

void command_start(int argc, char **argv) {
    if (!(argc == 2 || argc == 3) || (argc == 2 && argv[1][0] == '-'))
        help_start();
    bool daemon = false, shell = false;
    if (argc == 3) {
        if (EQUALS_CONST(argv[1], "-d")) {
            ++argv;
            daemon = true;
        } else if (EQUALS_CONST(argv[1], "-s")) {
            ++argv;
            shell = true;
        } else {
            write_const_stderr("Unknown option. Try \"container --help\" for more information.\n");
            exit(1);
        }
    }
    uint8 len = strlen(argv[1]);
    kill_if_running(argv[1], len);
    memcpy(buf, SLEN(PATH "/configs/"));
    memcpy(buf + strlen(PATH "/configs/"), argv[1], len + 1);
    int fd = _open(buf, O_RDONLY), s;
    if (lseek(fd, 0L, SEEK_END) >= sizeof(buf))
        error("Config file too big!");
    lseek(fd, 0L, SEEK_SET);
    memcpy(buf + strlen(PATH "/"), SLEN("logs/"));
    memcpy(buf + strlen(PATH "/logs/"), argv[1], len + 1);
    log_fd = _open(buf, O_CREAT | O_WRONLY | O_TRUNC);
    parse_config(fd);
    mount_dirs();
    prepare_cgroups(argv[1], len);
    start_cgroups(argv[1], len);
    free_linked_lists();
    close(log_fd);
    log_fd = 2;
    signal(SIGUSR1, do_nothing);
    pid_t pid;
    if (!(pid = fork())) {
        save_pid(argv[1], len);
        if (unshare(CLONE_NEWNS | config.namespaces) == -1)
            error("unshare failed!");
        kill(getppid(), SIGUSR1);
        sleep(2); // sleep until SIGUSR1
        char *init = config.init;
        int initfd;
        if (shell)
            init = get_shell();
        if (init[0] == '@')
            initfd = _open(init + 1, O_PATH);
        if (chdir(config.root) == -1 || chroot(config.root) == -1 || chdir("/") == -1)
            error("chroot failed!");
        mount("none", "tmp", "tmpfs", MS_NODEV | MS_NOSUID | MS_NOEXEC, NULL);
        mount("none", "dev/shm", "tmpfs", MS_NODEV | MS_NOSUID | MS_NOEXEC, NULL);
        chmod("tmp", 0777);
        chmod("dev/shm", 0777);
        if (!(pid = fork())) {
            if (config.namespaces & CLONE_NEWUTS && sethostname(argv[1], len))
                error("sethostname failed!");
            if (config.namespaces & CLONE_NEWPID && mount("proc", "proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) == -1)
                error("mount(/proc) failed!");
            if (prctl(PR_SET_PDEATHSIG, SIGKILL) == -1)
                error("prctl failed!");
            environ = NULL;
            if (init[0] == '@') {
                const char *_argv[] = {init + 1, NULL};
                execveat(initfd, "", _argv, NULL, AT_EMPTY_PATH);
                close(initfd); // CLOEXEC doesn't work with scripts with shebang as when the interpreter wants to read the file, it'd be already closed
            } else
                execl(init, init, NULL);
            error("execl/execveat returned.");
            exit(1);
        } else {
            close(initfd);
            waitpid(pid, &s, 0);
        }
    } else {
        sleep(2); // sleep until SIGUSR1
        memcpy(buf, SLEN("/proc/"));
        len = itoa(pid, buf + strlen("/proc/"));
        if (config.namespaces & CLONE_NEWUSER) {
            memcpy(buf + strlen("/proc/") + len, SBLEN("/uid_map"));
            fd = _open(buf, O_WRONLY);
            write(fd, SLEN("0 0 1\n1 10000 99999\n"));
            close(fd);
            buf[strlen("/proc/") + len + strlen("/")] = 'g';
            fd = _open(buf, O_WRONLY);
            write(fd, SLEN("0 0 1\n1 10000 99999\n"));
            close(fd);
        }
        if (config.namespaces & CLONE_NEWTIME) {
            memcpy(buf + strlen("/proc/") + len, SBLEN("/timens_offsets"));
            fd = _open(buf, O_WRONLY);
            int _fd = _open("/proc/uptime", O_RDONLY);
            if (read(_fd, buf, 256) < 1)
                error("read() failed!\n");
            close(_fd);
            char *p = buf + 256, *t = strchr(buf, '.');
            memcpy(p, SLEN("monotonic -"));
            memcpy(p + strlen("monotonic -"), buf, t - buf);
            p[strlen("monotonic -") + (t - buf)] = ' ';
            memcpy(p + strlen("monotonic -") + (t - buf) + 1, t + 1, 2);
            memcpy(p + strlen("monotonic -") + (t - buf) + 3, SLEN("0000000\n"));
            write(fd, p, strlen("monotonic -") + (t - buf) + 3 + strlen("0000000\n"));
            memcpy(p, "boottime ", strlen("boottime "));
            write(fd, p, strlen("boottime  -") + (t - buf) + 3 + strlen("0000000\n"));
            close(fd);
        }
        kill(pid, SIGUSR1);
        if (daemon || shell)
            waitpid(pid, &s, 0);
    }
}

void command_kill(int argc, char **argv) {
    if (argc != 2 || argv[1][0] == '-') {
        write_const_stderr("Usage: container kill {CONTAINER}\nKill a container.\n");
        exit(1);
    }
    char buf[64];
    uint8 len;
    chdir(PATH "/pids");
    int fd = _open(argv[1], O_RDONLY);
    if ((len = read(fd, buf, 63)) < 1) {
        write_const_stderr("Error: read() failed!\n");
        exit(2);
    }
    close(fd);
    unlink(argv[1]);
    buf[len] = '\0';
    kill(atoi(buf), 9) == -1;
}

void kill_zombie(int sig, siginfo_t *info, void *vp) {
    int s;
    waitpid(info->si_pid, &s, 0);
}

void command_start_all(int argc, char **argv) {
    if (argc != 1) {
        write_const_stderr("Usage: container start-all\nStart all containers.\n");
        exit(1);
    }
    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_sigaction = kill_zombie;  
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_RESTART | SA_SIGINFO;
    sigaction(SIGCHLD, &action, NULL);
    struct dirent *dir_entry;
    DIR *dir;
    if (!(dir = opendir(PATH "/configs")))
        exit(1);
    char *_argv[4] = {"start-vm", "-d", NULL, NULL};
    while (dir_entry = readdir(dir))
        if (memcmp(dir_entry->d_name, SBLEN(".")) && memcmp(dir_entry->d_name, SBLEN("..")) && !fork()) {
            _argv[2] = dir_entry->d_name;
            command_start((sizeof(_argv) / sizeof(_argv[0])) - 1, _argv);
            exit(10);
        }
    closedir(dir);
    for (;;)
        pause();
}

void command_list(int argc, char **argv) {
    if (argc != 1 && !(argc == 2 && EQUALS_CONST(argv[1], "-r"))) {
        write_const_stderr("Usage: container list [-r]\nList the containers, if -r is used only running containers will be displayed.\n");
        exit(1);
    }
    bool is_running;
    struct dirent *dir_entry;
    uint8 len, read_len;
    char whitespaces[32], buf[256];
    int fd;
    memcpy(buf, SLEN(PATH "/pids/"));
    memset(whitespaces, ' ', 32);
    DIR *dir;
    if (!(dir = opendir(PATH "/configs")))
        exit(1);
    write_const_stdout("NAME                            RUNNING\n");
    while (dir_entry = readdir(dir))
        if (memcmp(dir_entry->d_name, SBLEN(".")) && memcmp(dir_entry->d_name, SBLEN(".."))) {
            len = strlen(dir_entry->d_name);
            memcpy(buf + strlen(PATH "/pids/"), dir_entry->d_name, len + 1);
            is_running = (fd = open(buf, O_RDONLY)) != -1 && (read_len = read(fd, buf, 64)) != -1 && close(fd) != -1;
            if (is_running) {
                buf[read_len] = '\0';
                if (kill(atoi(buf), 0) == -1) // check whether process exists
                    is_running = false;
            }
            if ((argc == 2 && is_running) || argc != 2) {
                write(STDOUT, dir_entry->d_name, len);
                write(STDOUT, whitespaces, sizeof(whitespaces) - len);
                if (is_running)
                    write_const_stdout("Yes\n");
                else
                    write_const_stdout("No\n");
            }
        }
    closedir(dir);
}

int main(int argc, char **argv) {
    umask(0);
    if (argc < 2 || argv[1][0] == '-') {
        write_const_stderr("Usage: container [COMMAND] [OPTIONS...]\nCommands:\n\tstart [-d|-s] {CONTAINER}\n\tkill {CONTAINER}\n\tstart-all\n\tlist [-r]\nYou can get help for the subcommands using \"container [COMMAND] --help\".\n");
        return 0;
    }
    --argc, ++argv;
    if (EQUALS_CONST(argv[0], "start"))
        command_start(argc, argv);
    else if (EQUALS_CONST(argv[0], "kill"))
        command_kill(argc, argv);
    else if (EQUALS_CONST(argv[0], "start-all"))
        command_start_all(argc, argv);
    else if (EQUALS_CONST(argv[0], "list"))
        command_list(argc, argv);
    else {
        write_const_stderr("Unknown command. Try \"container --help\" for more information.\n");
        return 1;
    }
    return 0;
}