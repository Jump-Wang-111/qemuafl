#include "cgifuzz.h"

cgi_fd      *cgi_feedback;
int         use_cgi_feedback;
regex_env   *cgi_regex;
int         use_cgi_regex;
char        path_info[ENV_MAX_LEN - ENV_NAME_MAX_LEN];
int         path_info_len;
func_info   hook[FUNC_COUNT] = {
    [ENVIRON]       = {"environ", 0, 0, 0, 0, 0, 0},
    [GETENV]        = {"getenv", 0, 0, 0, 0, 0, 0},
    [REGCOMP]       = {"regcomp", 0, 0, 0, 0, 0, 0},
    [REGEXEC]       = {"regexec", 0, 0, 0, 0, 0, 0},
    [STRCMP]        = {"strcmp", 0, 0, 0, 0, 0, 0},
    [STRNCMP]       = {"strncmp", 0, 0, 0, 0, 0, 0},
    [STRCASECMP]    = {"strcasecmp", 0, 0, 0, 0, 0, 0},
    [STRNCASECMP]   = {"strncasecmp", 0, 0, 0, 0, 0, 0},
    [STRSTR]        = {"strstr", 0, 0, 0, 0, 0, 0},
    [STRTOK]        = {"strtok", 0, 0, 0, 0, 0, 0}
};

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

MapEntry** loadmaps() {
    
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) {
        perror("loadmaps: open");
        return NULL;
    }

    char* buf = (char* )malloc(1024*1024), *_buf = buf;
    int byte_read;
    while((byte_read = read(fd, _buf, 1024)) > 0) {
        _buf += byte_read;
    }
    int size = _buf - buf;
    buf[size] = 0;
    close(fd);

    int i = 0;
    MapEntry** maplist;
    maplist = (MapEntry**)malloc(1024 * sizeof(MapEntry*));
    char *line = strtok(buf, "\n");
    while (line != NULL) {
        MapEntry* entry = (MapEntry*)malloc(sizeof(MapEntry));
        parse_map_line(line, entry);
        maplist[i++] = entry;
        line = strtok(NULL, "\n");
    }
    maplist[i] = 0;

    return maplist;
}

int is_libc_mapping(char* path) {
    /* First match libc.so.6*/
    if(strstr(path, "libc.so.6") != NULL) {
        return 1;
    }

    /* Then match libc-<version>.so*/
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
        return 1; // Match
    } else if (ret == REG_NOMATCH) {
        return 0; // No match
    } else {
        char msgbuf[100];
        regerror(ret, &regex, msgbuf, sizeof(msgbuf));
        fprintf(stderr, "is_libc_mapping: Regex match failed: %s\n", msgbuf);
        exit(EXIT_FAILURE);
    }
}

void get_libc_info(MapEntry** maplist, uint64_t* start, char** path) {
    uint64_t end;
    int i = 0;
    for(i = 0; maplist[i]; i++) {
        MapEntry* entry = maplist[i];
        if (is_libc_mapping(entry->pathname)) {
            sscanf(entry->address, "%lx-%lx", start, &end);
            *path = entry->pathname;
            break;
        }
    }
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

Elf32_Addr get_sym_off(char *libc_path, char *sym_name) {
    int fd = open(libc_path, O_RDONLY);
    if (fd < 0) {
        perror("get_environ_off: open");
        return 1;
    }

    unsigned char e_ident[EI_NIDENT];
    read(fd, e_ident, EI_NIDENT);
    if (memcmp(e_ident, ELFMAG, SELFMAG) != 0) {
        perror("get_environ_off: Not an ELF file\n");
        close(fd);
        return 1;
    }

    lseek(fd, 0, SEEK_SET);
    
    Elf32_Ehdr ehdr;
    read(fd, &ehdr, sizeof(ehdr));

    Elf32_Shdr *shdrs;
    read_section_headers32(fd, &ehdr, &shdrs);

    for (int i = 0; i < ehdr.e_shnum; i++) {
        if (shdrs[i].sh_type != SHT_DYNSYM)
            continue;
        char *symtab, *strtab;
        Elf32_Shdr *strtab_hdr = &shdrs[shdrs[i].sh_link];
        read_section32(fd, &shdrs[i], &symtab);
        read_section32(fd, strtab_hdr, &strtab);

        int sym_count = shdrs[i].sh_size / shdrs[i].sh_entsize;
        for (int j = 0; j < sym_count; j++) {
            Elf32_Sym *sym = (Elf32_Sym *)(symtab + j * shdrs[i].sh_entsize);
            if (strcmp(&strtab[sym->st_name], sym_name) == 0) {
                if (getenv("CGI_DEBUG"))
                    fprintf(stderr, "Found symbol '%s' at address 0x%x\n", sym_name, sym->st_value);
                free(symtab);
                free(strtab);
                free(shdrs);
                close(fd);
                return sym->st_value;
            }
        }
    }

    fprintf(stderr, "Symbol '%s' not found\n", sym_name);
    free(shdrs);
    return 0;
}

void freemaps(MapEntry** maplist) {
    for(int i = 0; maplist[i]; i++) {
        free(maplist[i]);
  }
  free(maplist);
}

void debug_env(target_ulong g_environ) {
    target_ulong i;
    uint64_t g2h_environ = g2h_untagged(g_environ);
    for (i = 0; *(target_ulong*)(g2h_environ + i); i += 4) {
      fprintf(stderr, "[DEBUG] envp: %s\n", (char*)haddr_from_h(g2h_environ + i));
    }
    fprintf(stderr, "[DEBUG] totol: %d\n", i / 4);
}

void get_libc_sym_addr() {

    MapEntry** maplist = loadmaps();
    uint64_t start;
    target_ulong offset;
    char* libc_path;

    get_libc_info(maplist, &start, &libc_path);
    if (getenv("CGI_DEBUG")) {
        fprintf(stderr, "[DEBUG] libc_start: %lx\n", start);
        fprintf(stderr, "[DEBUG] libc_path: %s\n", libc_path);
    }

    for (int i = 0; i < FUNC_COUNT; i++) {
        
        offset = get_sym_off(libc_path, hook[i].name);
        if (!offset) continue;
        /*
            If the file specifies a load address, 
            the symbol table will return the actual address; 
            if the file does not specify a load address, 
            which defaults to 0, 
            then the address must be calculated manually.
        */
        if (offset >= h2g(start))
            hook[i].addr = offset;
        else
            hook[i].addr = h2g(start) + offset;
        
        if (getenv("CGI_DEBUG")) {
            fprintf(stderr, "[DEBUG] g_%s_addr: %08x\n", hook[i].name, hook[i].addr);
        }
    }

    freemaps(maplist);
}

char* get_guest_env(const char *name, char **env_list) {
  
    if (env_list == NULL || name[0] == '\0') return NULL;

    size_t len = strlen (name);
    for (target_ulong *ep = env_list; *ep; ++ep) {
        char *p = haddr_from_h(ep);
        if (name[0] == p[0]
            && strncmp (name, p, len) == 0 && p[len] == '=')
            return p + len + 1;
    }

    return NULL;
}

void set_guest_env(char *input, int length, char **env_list, char *env_strs) {
    
    // fprintf(stderr, "[DEBUG] input: %s\n", input);
    // fprintf(stderr, "[DEBUG] len: %d\n", length);
    // fprintf(stderr, "[DEBUG] strlen: %d\n", strlen(input));

    char *env_st = input, *ed = env_st + length, *env_end = env_st;
    
    // Save the original head of the env_list for later searches (e.g., get_guest_env)
    char **o_env_list = env_list;
    // fprintf(stderr, "[DEBUG] %x\n", env_list);

    // ========================================================================
    // Fuzzer-Controlled Variables (Client-Controlled)
    // ========================================================================
    // These variables are parsed from the fuzzer's input.
    // They typically represent HTTP headers (e.g., HTTP_USER_AGENT, HTTP_COOKIE).
    // ========================================================================
    while (env_st < ed) {

        while (*env_end != '\n') env_end++;
        *env_end++ = '\0';

        strncpy(env_strs, env_st, ENV_MAX_LEN - ENV_NAME_MAX_LEN);
        gval_from_h(env_list) = h2g(env_strs);
        if (getenv("CGI_DEBUG_ENV")) fprintf(stderr, "[DEBUG] Add env: %s\n", env_st);

        env_strs += ENV_MAX_LEN;
        env_list = (char **)((uint64_t)env_list + sizeof(target_ulong));

        env_st = env_end;
    }

    /* Cache some env */
    char *p = get_guest_env("PATH_INFO", o_env_list);
    
    if (p != NULL) {
        strncpy(path_info, p, ENV_MAX_LEN - ENV_NAME_MAX_LEN);
        path_info_len = strlen(path_info);
    }
    else {
        fprintf(stderr, "[WARN] No path_info\n");
    }

    /* CGI fuzz: hack stdin, from `afl-cgi-wrapper`*/
    int fds[2];
    if (pipe(fds)) {
        fprintf(stderr, "[ERROR] Fail to create pipe for stdin redirection\n");
        return;
    }

    // Redirect the read-end of the pipe to STDIN (fd 0)
    if (dup2(fds[0], STDIN_FILENO) == -1) {
        perror("[ERROR] dup2 failed");
        close(fds[0]);
        close(fds[1]);
        return;
    }
    // Close the original read-end fd, as it's now duplicated to 0
    close(fds[0]);

    char *content = get_guest_env("CONTENT", o_env_list);
    if (content) {
        int content_length = write(fds[1], content, strlen(content));
        if (content_length == -1) 
            fprintf(stderr, "[ERROR] Fail to write to pipe\n");
        
        /* set env for CONTENT_LENGTH */
        snprintf(env_strs, ENV_MAX_LEN, "CONTENT_LENGTH=%d", content_length);
        if (getenv("CGI_DEBUG_ENV")) fprintf(stderr, "%s\n", env_strs);
        
        gval_from_h(env_list) = h2g(env_strs);
        env_strs += ENV_MAX_LEN;
        
        env_list = (char **)((uint64_t)env_list + sizeof(target_ulong));
        
    }
    close(fds[1]);

    // ========================================================================
    // [END] Finalize the Environment List
    // ========================================================================
    // Ensure the array is NULL-terminated, as required by the execve spec.
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
        return;
    }
    int ret = lseek(fd, 0, SEEK_SET);
    if (ret < 0) {
        perror("seek set"); 
        return;
    }
    int inputlen = ENV_MAX_ENTRY * ENV_MAX_LEN;
    char *input = (char *)malloc(inputlen);
    if (input == NULL) {
        perror("malloc");
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

void set_guest_env_persistent(uint8_t *input_buf, uint32_t input_buf_len, char **env_list, char *env_strs) {
    set_guest_env((char *)input_buf, (int)input_buf_len, env_list, env_strs);
}

void set_feedback_env(char *env, char *func, char *fb) {
    
    if (cgi_feedback->tlen + strlen(fb) + strlen(func) + 3 > ENV_MAX_LEN) return;

    char *start = cgi_feedback->tlen + env;
    cgi_feedback->tlen += sprintf(start, "%s %s", func, fb) + 1;

    // fprintf(stderr, "[FB] start: %s\n", start);
    // fprintf(stderr, "[FB] tlen: %d\n", cgi_feedback->tlen);

    char *p = strchr(start, ' ');
    *p = '\0';

    if (getenv("HOOK_DEBUG")) {
        fprintf(stderr, "[FB] Set feedback env: %s-%s\n", start, p + 1);
    }

}