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
#include <stdbool.h>

#define gval_from_h(h_addr)     *(target_ulong *)(h_addr)
#define gval_from_g(g_addr)     gval_from_h(g2h_untagged(g_addr))
#define haddr_from_g(g_addr)    g2h_untagged(gval_from_g(g_addr))
#define haddr_from_h(h_addr)    g2h_untagged(gval_from_h(h_addr))

#define SHM_CGI_FD_ENV_VAR  "__AFL_SHM_CGI_FD_ID"
#define SHM_CGI_RE_ENV_VAR  "__AFL_SHM_CGI_RE_ID"
#define CGI_ENABLE_ENVBRIDGE_ENV "CGI_ENABLE_ENVBRIDGE"
#define CGI_ENABLE_FEEDBACK_ENV  "CGI_ENABLE_FEEDBACK"
#define CGI_ENABLE_CONTEXT_ENV   "CGI_ENABLE_CONTEXT"
#define AFL_CGI_ENABLE_ENVBRIDGE_ENV "AFL_CGI_ENABLE_ENVBRIDGE"
#define AFL_CGI_ENABLE_FEEDBACK_ENV  "AFL_CGI_ENABLE_FEEDBACK"
#define AFL_CGI_ENABLE_CONTEXT_ENV   "AFL_CGI_ENABLE_CONTEXT"
#define ENV_MAX_LEN         4096
#define FD_ENTRY_LEN        (4096 * 4)
#define ENV_MAX_ENTRY       256
#define ENV_NAME_MAX_LEN    128
#define NEW_ENV_FLAG        "NEW_ENV"
#define CGI_FEEDBACK_MAX_ENVS 32
#define CGI_FEEDBACK_MAX_PAIRS 64

#define QENTRY_GETSTR_OFF   24
#define QENTRY_GETINT_OFF   36

#define CGI_FAKE_HEAP_SIZE   (128 * 1024)

#define hash_map_int(x)     (((x) & 0x1ffff) >> 5)

typedef struct {
    char address[32];
    char perms[8];
    unsigned long offset;
    char dev[8];
    unsigned long inode;
    char pathname[512];
} MapEntry;

typedef enum {
    HOOK_RESOLVE_LIBC_SYM = 0,
    HOOK_RESOLVE_MOD_SYM,
    HOOK_RESOLVE_MOD_OFFSET,
    HOOK_RESOLVE_RUNTIME
} hook_resolve_t;

typedef struct {
    char            name[64];
    char            module_match[128];
    hook_resolve_t  resolve_type;
    target_ulong    offset;      /* for MOD_OFFSET */
    target_ulong    addr;
    target_ulong    ret_addr;
    target_ulong    arg1;
    target_ulong    arg2;
    target_ulong    arg3;
    target_ulong    arg4;
    bool            enabled;
} func_info;

/* Func to hook */
enum {
    ENVIRON,
    GETENV,
    REGCOMP,
    REGEXEC,
    STRCMP,
    STRNCMP,
    STRCASECMP,
    STRNCASECMP,
    STRSTR,
    STRTOK,
    FREE,

    /* qcgi / oem */
    QENTRY,
    QCGISESS_OEM_INIT,

    /* runtime discovered from qEntry object */
    QENTRY_GETSTR,
    QENTRY_GETINT,

    FUNC_COUNT
};

typedef struct cgi_fd {
    int   num;
    int   stage;
    int   target;
    int   pair;
    int   tlen;
    char  buf[0];
} cgi_fd;

typedef struct regex_env {
    u8    all_regex_map[1 << 12];
    char  all_regex_val[1 << 12][1 << 8];

    char  env_name[128];
    u8    path_info_map[1 << 12];
    int   num_of_regex;
    char  path_info_str[1 << 12][1 << 8];
    char  path_info_r[1 << 12][1 << 8];
} regex_env;

typedef struct {
    target_ulong base;
    target_ulong cur;
    target_ulong end;
    bool         enabled;
} cgi_fake_heap_t;

extern cgi_fd         *cgi_feedback;
extern int            use_cgi_feedback;
extern int            feedback_stage;
extern regex_env      *cgi_regex;
extern int            use_cgi_regex;
extern func_info      hook[FUNC_COUNT];
extern cgi_fake_heap_t cgi_fake_heap;

extern char           path_info[ENV_MAX_LEN - ENV_NAME_MAX_LEN];
extern int            path_info_len;

extern bool           cgi_persistent;
extern bool           cgi_debug_env;
extern bool           cgi_test_crash;
extern bool           cgi_debug;
extern bool           hook_debug;

void parse_map_line(char *line, MapEntry *entry);
MapEntry **loadmaps(void);
void freemaps(MapEntry **maplist);

int is_libc_mapping(char *path);
int path_matches_module(const char *path, const char *module_match);

void get_libc_info(MapEntry **maplist, uint64_t *start, char **path);
int get_module_info(MapEntry **maplist, const char *module_match, uint64_t *start, char **path);

void read_section_headers32(int fd, Elf32_Ehdr *ehdr, Elf32_Shdr **shdrs);
void read_section32(int fd, Elf32_Shdr *shdr, char **buffer);

Elf32_Addr get_sym_off(char *elf_path, char *sym_name);

void debug_env(target_ulong g_environ);

/* old name kept for compatibility */
// void get_libc_sym_addr(void);
void resolve_hook_addrs(void);
int cgi_envbridge_feature_enabled(void);
int cgi_feedback_feature_enabled(void);
int cgi_context_feature_enabled(void);

char *get_guest_env(const char *name, char **env_list);
void set_guest_env(char *input, int length, char **env_list, char *env_strs);
void set_guest_env_file(char *inputfile, char **env_list, char *env_strs);
void cheat_persistent_ptr(struct api_regs *, uint64_t, uint8_t *, uint32_t);
void set_guest_env_persistent(uint8_t *input_buf, uint32_t input_buf_len,
                              char **env_list, char *env_strs);
int set_feedback_env(char *env, char *func, char *fb);

/* role / fake heap helpers */
int  get_role_by_env(char **env_list);

void cgi_fake_heap_set_range(target_ulong guest_base, target_ulong size);
void cgi_fake_heap_reset(void);
bool cgi_fake_heap_contains(target_ulong gptr);
target_ulong cgi_fake_heap_alloc(size_t size);
target_ulong cgi_fake_heap_strdup(const char *src);

/* ARM32 helper-side hook functions */
static inline void cgi_force_ret(CPUArchState *env, target_ulong retval);
void cgi_get_qcgisess_oem_init_arg(CPUArchState *env);
void cgi_get_qentry_arg(CPUArchState *env);
void cgi_get_qentry_ret(CPUArchState *env, target_ulong pc);
void cgi_get_qentry_getint_arg(CPUArchState *env, char **env_list);
void cgi_get_qentry_getstr_arg(CPUArchState *env, char **env_list);
void cgi_get_free_arg(CPUArchState *env);

#endif
