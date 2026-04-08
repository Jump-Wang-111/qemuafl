#include "cgifuzz.h"

cgi_fd      *cgi_feedback;
int         use_cgi_feedback;
regex_env   *cgi_regex;
int         use_cgi_regex;
char        path_info[ENV_MAX_LEN - ENV_NAME_MAX_LEN];
int         path_info_len;
cgi_fake_heap_t cgi_fake_heap = {0};

func_info hook[FUNC_COUNT] = {
    [ENVIRON] = {
        .name = "environ",
        .module_match = "libc",
        .resolve_type = HOOK_RESOLVE_LIBC_SYM,
        .enabled = true,
    },
    [GETENV] = {
        .name = "getenv",
        .module_match = "libc",
        .resolve_type = HOOK_RESOLVE_LIBC_SYM,
        .enabled = true,
    },
    [REGCOMP] = {
        .name = "regcomp",
        .module_match = "libc",
        .resolve_type = HOOK_RESOLVE_LIBC_SYM,
        .enabled = true,
    },
    [REGEXEC] = {
        .name = "regexec",
        .module_match = "libc",
        .resolve_type = HOOK_RESOLVE_LIBC_SYM,
        .enabled = true,
    },
    [STRCMP] = {
        .name = "strcmp",
        .module_match = "libc",
        .resolve_type = HOOK_RESOLVE_LIBC_SYM,
        .enabled = true,
    },
    [STRNCMP] = {
        .name = "strncmp",
        .module_match = "libc",
        .resolve_type = HOOK_RESOLVE_LIBC_SYM,
        .enabled = true,
    },
    [STRCASECMP] = {
        .name = "strcasecmp",
        .module_match = "libc",
        .resolve_type = HOOK_RESOLVE_LIBC_SYM,
        .enabled = true,
    },
    [STRNCASECMP] = {
        .name = "strncasecmp",
        .module_match = "libc",
        .resolve_type = HOOK_RESOLVE_LIBC_SYM,
        .enabled = true,
    },
    [STRSTR] = {
        .name = "strstr",
        .module_match = "libc",
        .resolve_type = HOOK_RESOLVE_LIBC_SYM,
        .enabled = true,
    },
    [STRTOK] = {
        .name = "strtok",
        .module_match = "libc",
        .resolve_type = HOOK_RESOLVE_LIBC_SYM,
        .enabled = true,
    },
    [FREE] = {
        .name = "free",
        .module_match = "libc",
        .resolve_type = HOOK_RESOLVE_LIBC_SYM,
        .enabled = true,
    },

    /*
     * 这里改成你 maps 里实际能匹配到的模块关键字
     */
    [QENTRY] = {
        .name = "qEntry",
        .module_match = "libqdecoder",
        .resolve_type = HOOK_RESOLVE_MOD_SYM,
        .enabled = true,
    },

    /*
     * 如果 qcgisess_oem_init 不导出，优先用 MOD_OFFSET
     * 半自动获取
     */
    [QCGISESS_OEM_INIT] = {
        .name = "qcgisess_oem_init",
        .module_match = "spx_restservice",
        .resolve_type = HOOK_RESOLVE_MOD_OFFSET,
        .offset = 0x0,   /* TODO */
        .enabled = true,
    },

    [QENTRY_GETSTR] = {
        .name = "qentry.getstr",
        .resolve_type = HOOK_RESOLVE_RUNTIME,
        .enabled = false,
    },
    [QENTRY_GETINT] = {
        .name = "qentry.getint",
        .resolve_type = HOOK_RESOLVE_RUNTIME,
        .enabled = false,
    },
};

bool cgi_persistent = false;
bool cgi_debug_env = false;
bool cgi_test_crash = false;
bool cgi_debug = false;
bool hook_debug = false;

static int cgi_flag_value_enabled(const char *value, int default_value) {
    if (!value || !*value) {
        return default_value;
    }

    if (!strcmp(value, "0") || !strcmp(value, "off") ||
        !strcmp(value, "false") || !strcmp(value, "no")) {
        return 0;
    }

    if (!strcmp(value, "1") || !strcmp(value, "on") ||
        !strcmp(value, "true") || !strcmp(value, "yes")) {
        return 1;
    }

    return default_value;
}

static int cgi_flag_enabled_compat(const char *name, const char *legacy_name,
                                   int default_value) {
    const char *value = getenv(name);
    if (!value || !*value) {
        value = getenv(legacy_name);
    }
    return cgi_flag_value_enabled(value, default_value);
}

int cgi_feedback_feature_enabled(void) {
    return cgi_flag_enabled_compat(CGI_ENABLE_FEEDBACK_ENV,
                                   AFL_CGI_ENABLE_FEEDBACK_ENV, 1);
}

int cgi_envbridge_feature_enabled(void) {
    return cgi_flag_enabled_compat(CGI_ENABLE_ENVBRIDGE_ENV,
                                   AFL_CGI_ENABLE_ENVBRIDGE_ENV, 1);
}

int cgi_context_feature_enabled(void) {
    return cgi_flag_enabled_compat(CGI_ENABLE_CONTEXT_ENV,
                                   AFL_CGI_ENABLE_CONTEXT_ENV, 1);
}

static void reset_hook_state(int idx) {
    hook[idx].addr = 0;
    hook[idx].ret_addr = 0;
    hook[idx].arg1 = 0;
    hook[idx].arg2 = 0;
    hook[idx].arg3 = 0;
    hook[idx].arg4 = 0;
}

static void configure_cgi_hook_groups(void) {
    int envbridge_enabled = cgi_envbridge_feature_enabled();
    int feedback_enabled = cgi_feedback_feature_enabled() && envbridge_enabled;
    int context_enabled = cgi_context_feature_enabled() && envbridge_enabled;
    int feedback_hooks[] = {
        GETENV, REGCOMP, REGEXEC, STRCMP, STRNCMP,
        STRCASECMP, STRNCASECMP, STRSTR, STRTOK
    };
    int context_hooks[] = {
        FREE, QENTRY, QCGISESS_OEM_INIT
    };

    hook[ENVIRON].enabled = envbridge_enabled;
    if (!envbridge_enabled) {
        reset_hook_state(ENVIRON);
    }

    for (size_t i = 0; i < sizeof(feedback_hooks) / sizeof(feedback_hooks[0]); ++i) {
        hook[feedback_hooks[i]].enabled = feedback_enabled;
        if (!feedback_enabled) {
            reset_hook_state(feedback_hooks[i]);
        }
    }

    for (size_t i = 0; i < sizeof(context_hooks) / sizeof(context_hooks[0]); ++i) {
        hook[context_hooks[i]].enabled = context_enabled;
        if (!context_enabled) {
            reset_hook_state(context_hooks[i]);
        }
    }

    if (!context_enabled) {
        hook[QENTRY_GETSTR].enabled = false;
        hook[QENTRY_GETINT].enabled = false;
        reset_hook_state(QENTRY_GETSTR);
        reset_hook_state(QENTRY_GETINT);
    }
}

static inline size_t align_up(size_t x, size_t a) {
    return (x + a - 1) & ~(a - 1);
}

void parse_map_line(char *line, MapEntry *entry) {
    int fields = sscanf(line, "%31s %7s %lx %7s %lu %255s[^\n]",
                        entry->address,
                        entry->perms,
                        &entry->offset,
                        entry->dev,
                        &entry->inode,
                        entry->pathname);
    if (fields < 6) {
        entry->pathname[0] = '\0';
    }
}

MapEntry **loadmaps(void) {
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) {
        perror("loadmaps: open");
        return NULL;
    }

    char *buf = (char *)malloc(1024 * 1024), *_buf = buf;
    int byte_read;
    while ((byte_read = read(fd, _buf, 1024)) > 0) {
        _buf += byte_read;
    }
    int size = _buf - buf;
    buf[size] = 0;
    close(fd);

    int i = 0;
    MapEntry **maplist = (MapEntry **)malloc(1024 * sizeof(MapEntry *));
    char *line = strtok(buf, "\n");
    while (line != NULL) {
        MapEntry *entry = (MapEntry *)malloc(sizeof(MapEntry));
        parse_map_line(line, entry);
        maplist[i++] = entry;
        line = strtok(NULL, "\n");
    }
    maplist[i] = 0;

    return maplist;
}

void freemaps(MapEntry **maplist) {
    for (int i = 0; maplist[i]; i++) {
        free(maplist[i]);
    }
    free(maplist);
}

int is_libc_mapping(char *path) {
    if (strstr(path, "libc.so.6") != NULL) {
        return 1;
    }

    const char *pattern = "libc-[0-9]+\\.[0-9]+\\.so";
    regex_t regex;
    int ret;

    ret = regcomp(&regex, pattern, REG_EXTENDED);
    if (ret) {
        fprintf(stderr, "is_libc_mapping: Could not compile regex\n");
        exit(EXIT_FAILURE);
    }

    ret = regexec(&regex, path, 0, NULL, 0);
    regfree(&regex);

    if (!ret) {
        return 1;
    } else if (ret == REG_NOMATCH) {
        return 0;
    } else {
        char msgbuf[100];
        regerror(ret, &regex, msgbuf, sizeof(msgbuf));
        fprintf(stderr, "is_libc_mapping: Regex match failed: %s\n", msgbuf);
        exit(EXIT_FAILURE);
    }
}

int path_matches_module(const char *path, const char *module_match) {
    if (!path || !module_match || !module_match[0]) {
        return 0;
    }
    if (!strcmp(module_match, "libc")) {
        return is_libc_mapping((char *)path);
    }
    return strstr(path, module_match) != NULL;
}

void get_libc_info(MapEntry **maplist, uint64_t *start, char **path) {
    uint64_t end;
    for (int i = 0; maplist[i]; i++) {
        MapEntry *entry = maplist[i];
        if (is_libc_mapping(entry->pathname)) {
            sscanf(entry->address, "%lx-%lx", start, &end);
            *path = entry->pathname;
            return;
        }
    }
    *start = 0;
    *path = NULL;
}

int get_module_info(MapEntry **maplist, const char *module_match,
                    uint64_t *start, char **path) {
    uint64_t end;

    for (int i = 0; maplist[i]; i++) {
        MapEntry *entry = maplist[i];

        if (!entry->pathname[0]) continue;
        if (entry->perms[0] != 'r' || entry->perms[2] != 'x') continue;
        if (!path_matches_module(entry->pathname, module_match)) continue;

        sscanf(entry->address, "%lx-%lx", start, &end);
        *path = entry->pathname;
        return 1;
    }

    *start = 0;
    *path = NULL;
    return 0;
}

void read_section_headers32(int fd, Elf32_Ehdr *ehdr, Elf32_Shdr **shdrs) {
    *shdrs = malloc(ehdr->e_shentsize * ehdr->e_shnum);
    lseek(fd, ehdr->e_shoff, SEEK_SET);
    read(fd, *shdrs, ehdr->e_shentsize * ehdr->e_shnum);
}

void read_section32(int fd, Elf32_Shdr *shdr, char **buffer) {
    *buffer = malloc(shdr->sh_size);
    lseek(fd, shdr->sh_offset, SEEK_SET);
    read(fd, *buffer, shdr->sh_size);
}

Elf32_Addr get_sym_off(char *elf_path, char *sym_name) {
    int fd = open(elf_path, O_RDONLY);
    if (fd < 0) {
        perror("get_sym_off: open");
        return 0;
    }

    unsigned char e_ident[EI_NIDENT];
    read(fd, e_ident, EI_NIDENT);
    if (memcmp(e_ident, ELFMAG, SELFMAG) != 0) {
        close(fd);
        return 0;
    }

    lseek(fd, 0, SEEK_SET);

    Elf32_Ehdr ehdr;
    read(fd, &ehdr, sizeof(ehdr));

    Elf32_Shdr *shdrs;
    read_section_headers32(fd, &ehdr, &shdrs);

    for (int i = 0; i < ehdr.e_shnum; i++) {
        if (shdrs[i].sh_type != SHT_DYNSYM) continue;

        char *symtab, *strtab;
        Elf32_Shdr *strtab_hdr = &shdrs[shdrs[i].sh_link];
        read_section32(fd, &shdrs[i], &symtab);
        read_section32(fd, strtab_hdr, &strtab);

        int sym_count = shdrs[i].sh_size / shdrs[i].sh_entsize;
        for (int j = 0; j < sym_count; j++) {
            Elf32_Sym *sym = (Elf32_Sym *)(symtab + j * shdrs[i].sh_entsize);
            if (strcmp(&strtab[sym->st_name], sym_name) == 0) {
                free(symtab);
                free(strtab);
                free(shdrs);
                close(fd);
                return sym->st_value;
            }
        }

        free(symtab);
        free(strtab);
    }

    free(shdrs);
    close(fd);
    return 0;
}

void debug_env(target_ulong g_environ) {
    target_ulong i;
    uint64_t g2h_environ = g2h_untagged(g_environ);
    for (i = 0; *(target_ulong *)(g2h_environ + i); i += 4) {
        fprintf(stderr, "[DEBUG] envp: %s\n",
                (char *)haddr_from_h(g2h_environ + i));
    }
    fprintf(stderr, "[DEBUG] total: %d\n", i / 4);
}

void resolve_hook_addrs(void) {
    configure_cgi_hook_groups();

    MapEntry **maplist = loadmaps();
    if (!maplist) return;

    for (int i = 0; i < FUNC_COUNT; i++) {
        uint64_t base = 0;
        char *path = NULL;
        target_ulong off = 0;

        if (!hook[i].enabled) continue;
        if (hook[i].resolve_type == HOOK_RESOLVE_RUNTIME) continue;

        switch (hook[i].resolve_type) {
        case HOOK_RESOLVE_LIBC_SYM:
            get_libc_info(maplist, &base, &path);
            if (!path) continue;
            off = get_sym_off(path, hook[i].name);
            if (!off) continue;
            hook[i].addr = (off >= h2g(base)) ? off : h2g(base) + off;
            break;

        case HOOK_RESOLVE_MOD_SYM:
            if (!get_module_info(maplist, hook[i].module_match, &base, &path)) continue;
            off = get_sym_off(path, hook[i].name);
            if (!off) continue;
            hook[i].addr = (off >= h2g(base)) ? off : h2g(base) + off;
            break;

        case HOOK_RESOLVE_MOD_OFFSET:
            if (!get_module_info(maplist, hook[i].module_match, &base, &path)) continue;
            off = get_sym_off(path, hook[i].name);
            if (!off) {
                hook[i].addr = h2g(base) + hook[i].offset;
                continue;
            }
            hook[i].addr = (off >= h2g(base)) ? off : h2g(base) + off;
            break;

        case HOOK_RESOLVE_RUNTIME:
        default:
            break;
        }

        if (cgi_debug && hook[i].addr) {
            fprintf(stderr, "[DEBUG] g_%s_addr: %08x\n", hook[i].name, hook[i].addr);
        }
    }

    freemaps(maplist);
}

/* 兼容你现在已有调用点 */
// void get_libc_sym_addr(void) {
//     resolve_hook_addrs();
// }

char *get_guest_env(const char *name, char **env_list) {
    if (env_list == NULL || name[0] == '\0') return NULL;

    size_t len = strlen(name);
    for (target_ulong *ep = (target_ulong *)env_list; *ep; ++ep) {
        char *p = haddr_from_h(ep);
        if (name[0] == p[0] &&
            strncmp(name, p, len) == 0 &&
            p[len] == '=') {
            return p + len + 1;
        }
    }

    return NULL;
}

int get_role_by_env(char **env_list) {
    char *p;

    p = get_guest_env("HTTP_USERNAME", env_list);
    if (p && *p) {
        if (!strcasecmp(p, "admin"))    return 4;
        if (!strcasecmp(p, "operator")) return 3;
        if (!strcasecmp(p, "user"))     return 2;
        if (!strcasecmp(p, "guest"))    return 1;
    }

    return 0;
}

void set_guest_env(char *input, int length, char **env_list, char *env_strs) {
    
    cgi_fake_heap_reset();

    char *env_st = input, *ed = env_st + length, *env_end = env_st;
    char **o_env_list = env_list;

    char *binary_content_ptr = NULL;
    int binary_content_len = 0;

    while (env_st < ed) {
        if (strncmp(env_st, "CONTENT=", 8) == 0) {
            binary_content_ptr = env_st + 8;
            binary_content_len = ed - binary_content_ptr;
            break;
        }

        while (*env_end != '\n') env_end++;
        *env_end++ = '\0';

        strncpy(env_strs, env_st, ENV_MAX_LEN - ENV_NAME_MAX_LEN);
        gval_from_h(env_list) = h2g(env_strs);
        if (cgi_debug_env) fprintf(stderr, "[DEBUG] Add env: %s\n", env_st);

        env_strs += ENV_MAX_LEN;
        env_list = (char **)((uint64_t)env_list + sizeof(target_ulong));
        env_st = env_end;
    }

    char *p = get_guest_env("PATH_INFO", o_env_list);
    if (p != NULL) {
        strncpy(path_info, p, ENV_MAX_LEN - ENV_NAME_MAX_LEN);
        path_info_len = strlen(path_info);
    } else {
        fprintf(stderr, "[WARN] No path_info\n");
    }

    int fds[2];
    if (pipe(fds)) {
        fprintf(stderr, "[ERROR] Fail to create pipe for stdin redirection\n");
        return;
    }

    if (dup2(fds[0], STDIN_FILENO) == -1) {
        perror("[ERROR] dup2 failed");
        close(fds[0]);
        close(fds[1]);
        return;
    }
    close(fds[0]);

    if (binary_content_ptr && binary_content_len > 0) {
        if (cgi_debug_env) fprintf(stderr, "[DEBUG] Redirect stdin: %s\n", binary_content_ptr);
        if (write(fds[1], binary_content_ptr, binary_content_len) == -1) {
            fprintf(stderr, "[ERROR] Fail to write to pipe\n");
        }
    }
    close(fds[1]);

    gval_from_h(env_list) = 0;
}

void set_guest_env_file(char *inputfile, char **env_list, char *env_strs) {
    int fd = open(inputfile, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return;
    }

    int size = lseek(fd, 0, SEEK_END);
    if (size < 0) {
        perror("seek end");
        close(fd);
        return;
    }

    int ret = lseek(fd, 0, SEEK_SET);
    if (ret < 0) {
        perror("seek set");
        close(fd);
        return;
    }

    int inputlen = ENV_MAX_ENTRY * ENV_MAX_LEN;
    char *input = (char *)malloc(inputlen);
    if (input == NULL) {
        perror("malloc");
        close(fd);
        return;
    }

    int bytes_read = read(fd, input, inputlen);
    close(fd);

    set_guest_env(input, bytes_read, env_list, env_strs);
    free(input);
}

void cheat_persistent_ptr(struct api_regs *regs, uint64_t guest_base,
                          uint8_t *input_buf, uint32_t input_buf_len) {
    return;
}

void set_guest_env_persistent(uint8_t *input_buf, uint32_t input_buf_len,
                              char **env_list, char *env_strs) {
    set_guest_env((char *)input_buf, (int)input_buf_len, env_list, env_strs);
}

int set_feedback_env(char *env, char *func, char *fb) {
    if (!cgi_feedback || !env || !func || !fb) return 0;

    size_t remaining = ENV_MAX_LEN - cgi_feedback->tlen;
    if (remaining < 3) return 0;

    char *start = env + cgi_feedback->tlen;
    int written = snprintf(start, remaining, "%s %s", func, fb);
    if (written <= 0 || (size_t)written + 1 > remaining) {
        return 0;
    }

    char *p = strchr(start, ' ');
    if (!p) {
        start[0] = '\0';
        return 0;
    }

    *p = '\0';
    cgi_feedback->tlen += written + 1;

    if (hook_debug) {
        fprintf(stderr, "[FB] Set feedback env: %s-%s\n", start, p + 1);
    }

    return 1;
}

/* ---------------- fake heap ---------------- */

void cgi_fake_heap_set_range(target_ulong guest_base, target_ulong size) {
    cgi_fake_heap.base = guest_base;
    cgi_fake_heap.cur = guest_base;
    cgi_fake_heap.end = guest_base + size;
    cgi_fake_heap.enabled = (guest_base != 0 && size != 0);
}

void cgi_fake_heap_reset(void) {
    if (cgi_fake_heap.enabled) {
        cgi_fake_heap.cur = cgi_fake_heap.base;
    }
}

bool cgi_fake_heap_contains(target_ulong gptr) {
    if (!cgi_fake_heap.enabled) return false;
    return (gptr >= cgi_fake_heap.base && gptr < cgi_fake_heap.cur);
}

target_ulong cgi_fake_heap_alloc(size_t size) {
    size = align_up(size, 8);

    if (!cgi_fake_heap.enabled) return 0;
    if (cgi_fake_heap.cur + size > cgi_fake_heap.end) return 0;

    target_ulong gptr = cgi_fake_heap.cur;
    cgi_fake_heap.cur += size;
    return gptr;
}

target_ulong cgi_fake_heap_strdup(const char *src) {
    if (!src) return 0;

    size_t len = strlen(src) + 1;
    target_ulong gptr = cgi_fake_heap_alloc(len);
    if (!gptr) return 0;

    memcpy(g2h_untagged(gptr), src, len);
    return gptr;
}
