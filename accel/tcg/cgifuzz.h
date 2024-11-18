#ifndef __CGIFUZZ_H
#define __CGIFUZZ_H

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qemu/qemu-print.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "tcg/tcg.h"

#include "qemuafl/common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <regex.h>
#include <time.h>

#define gval_from_h(h_addr)     *(target_ulong*)(h_addr)
#define gval_from_g(g_addr)     gval_from_h(g2h_untagged(g_addr))
#define haddr_from_g(g_addr)    g2h_untagged(gval_from_g(g_addr))
#define haddr_from_h(h_addr)    g2h_untagged(gval_from_h(h_addr))

#define SHM_CGI_FD_ENV_VAR  "__AFL_SHM_CGI_FD_ID"
#define SHM_CGI_RE_ENV_VAR  "__AFL_SHM_CGI_RE_ID"
#define ENV_MAX_LEN         4096
#define ENV_MAX_ENTRY       256
#define ENV_NAME_MAX_LEN    128

#define hash_map_int(x)     (x & 0xffff) >> 4

typedef struct {
    char address[32];
    char perms[8];
    unsigned long offset;
    char dev[8];
    unsigned long inode;
    char pathname[512];
} MapEntry;

typedef struct {
    char            name[64];
    target_ulong    addr;
    target_ulong    ret_addr;
    target_ulong    arg1;
    target_ulong    arg2;
    target_ulong    arg3;
    target_ulong    arg4;
} func_info;

/* Func to hook */
enum {
    ENVIRON,
    GETENV,
    REGCOMP,
    REGEXEC,
    FUNC_COUNT
};

typedef struct cgi_fd {
  u32   num;
  char  buf[0];
} cgi_fd;

typedef struct regex_env {
  u8        all_regex_map[1 << 12];
  char      all_regex_val[1 << 12][1 << 8];

  char      env_name[128];
  u8        path_info_map[1 << 12];
  int       num_of_regex;
  char      path_info_str[1 << 12][1 << 8];
  char      path_info_r[1 << 12][1 << 8];
} regex_env;

extern cgi_fd       *cgi_feedback;
extern regex_env    *cgi_regex;
extern func_info    hook[FUNC_COUNT];
extern char         path_info[ENV_NAME_MAX_LEN];;
extern int          path_info_len;

void parse_map_line(char *line, MapEntry *entry);

MapEntry** loadmaps(void);

int is_libc_mapping(char* path);

void get_libc_info(MapEntry** maplist, uint64_t* start, char** path);

void read_section_headers32(int fd, Elf32_Ehdr *ehdr, Elf32_Shdr **shdrs);

void read_section32(int fd, Elf32_Shdr *shdr, char **buffer);

Elf32_Addr get_sym_off(char *libc_path, char *sym_name);

void freemaps(MapEntry** maplist);

void debug_env(target_ulong g_environ);

void get_libc_sym_addr(void);

char* get_guest_env(const char *name, char **env_list);

void set_guest_env(char *input, int length, char **env_list, char *env_strs);

void set_guest_env_file(char *inputfile, char **env_list, char *env_strs);

void cheat_persistent_ptr(struct api_regs *, uint64_t , uint8_t *, uint32_t );

void set_guest_env_persistent(uint8_t *input_buf, uint32_t input_buf_len, char **env_list, char *env_strs);

#endif