#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <regex.h>

#define g_value(g_addr)     *(abi_ulong*)g2h_untagged(g_addr)
#define g_haddr(g_addr)     g2h_untagged(g_value(g_addr))
#define h_gaddr(h_addr)     *(abi_ulong*)(h_addr)
#define h_haddr(h_addr)     g2h_untagged(h_gaddr(h_addr))

#define ENV_MAX_LEN 4096

typedef struct {
    char address[32];
    char perms[8];
    unsigned long offset;
    char dev[8];
    unsigned long inode;
    char pathname[1024];
} MapEntry;

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

Elf32_Addr get_environ_off(char* libc_path) {
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
            if (strcmp(&strtab[sym->st_name], "environ") == 0) {
                if (getenv("AFL_DEBUG"))
                    fprintf(stderr, "Found symbol 'environ' at address 0x%x\n", sym->st_value);
                free(symtab);
                free(strtab);
                free(shdrs);
                close(fd);
                return sym->st_value;
            }
        }
    }
    if (getenv("AFL_DEBUG"))
        fprintf(stderr, "Symbol 'environ' not found\n");
    free(shdrs);
    return 0;
}

void freemaps(MapEntry** maplist) {
    for(int i = 0; maplist[i]; i++) {
        free(maplist[i]);
  }
  free(maplist);
}

void debug_env(abi_ulong g_environ) {
    abi_ulong i;
    uint64_t g2h_environ = g2h_untagged(g_environ);
    for (i = 0; *(abi_ulong*)(g2h_environ + i); i += 4) {
      fprintf(stderr, "[DEBUG] envp: %s\n", (char*)h_haddr(g2h_environ + i));
    }
    fprintf(stderr, "[DEBUG] totol: %d\n", i / 4);
}

uint64_t libc_environ_addr() {
    MapEntry** maplist = loadmaps();

    uint64_t start;
    char* libc_path;
    get_libc_info(maplist, &start, &libc_path);
    
    uint64_t offset = get_environ_off(libc_path);
    uint64_t g2h_environ_addr = start + offset;

    abi_ulong g_environ_addr = h2g(g2h_environ_addr);
    abi_ulong g_environ = h_gaddr(g2h_environ_addr);
    
    if (getenv("AFL_DEBUG")) {
        fprintf(stderr, "[DEBUG] libc_start: %lx\n", start);
        fprintf(stderr, "[DEBUG] libc_path: %s\n", libc_path);
        fprintf(stderr, "[DEBUG] g_environ_addr: %08x\n", g_environ_addr);
        fprintf(stderr, "[DEBUG] g_environ: %08x\n", g_environ);
        // debug_env(g_environ);
    }

    freemaps(maplist);
    return g2h_environ_addr;
}