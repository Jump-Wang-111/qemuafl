/* Code to mangle pathnames into those matching a given prefix.
   eg. open("/lib/foo.so") => open("/usr/gnemul/i386-linux/lib/foo.so");

   The assumption is that this area does not change.
*/
#include "qemu/osdep.h"
#include <sys/param.h>
#include <dirent.h>
#include "qemu/cutils.h"
#include "qemu/path.h"
#include "qemu/thread.h"

static const char *base;
static GHashTable *hash;
static QemuMutex lock;
static char **strict_root_prefixes;

/*
 * QEMU user-mode normally falls back to the host path when a guest absolute
 * path is absent below QEMU_LD_PREFIX.  That is useful for loader support and
 * preloaded host-side helpers, but it lets missing runtime state such as
 * /var/* leak between otherwise isolated execution roots.  Keep the legacy
 * behavior by default and allow AFL's harness to make selected runtime
 * prefixes root-strict.
 */
static bool path_is_strict_root_prefix(const char *name)
{
    size_t prefix_len;
    const char *prefix;
    char **entry;

    if (!strict_root_prefixes) {
        return false;
    }

    for (entry = strict_root_prefixes; *entry; entry++) {
        prefix = *entry;
        prefix_len = strlen(prefix);
        while (prefix_len > 1 && prefix[prefix_len - 1] == '/') {
            prefix_len--;
        }

        if (prefix_len == 0 || prefix[0] != '/') {
            continue;
        }
        if (!strncmp(name, prefix, prefix_len) &&
            (name[prefix_len] == '\0' || name[prefix_len] == '/')) {
            return true;
        }
    }

    return false;
}

void init_paths(const char *prefix)
{
    const char *strict_prefixes;

    if (prefix[0] == '\0' || !strcmp(prefix, "/")) {
        return;
    }

    if (prefix[0] == '/') {
        base = g_strdup(prefix);
    } else {
        char *cwd = g_get_current_dir();
        base = g_build_filename(cwd, prefix, NULL);
        g_free(cwd);
    }

    hash = g_hash_table_new(g_str_hash, g_str_equal);
    qemu_mutex_init(&lock);

    strict_prefixes = getenv("AFL_QEMU_STRICT_ROOT_PATHS");
    if (strict_prefixes && strict_prefixes[0] != '\0') {
        strict_root_prefixes = g_strsplit(strict_prefixes, ",", -1);
    }
}

/* Look for path in emulation dir, otherwise return name. */
const char *path(const char *name)
{
    gpointer key, value;
    const char *ret;

    /* Only do absolute paths: quick and dirty, but should mostly be OK.  */
    if (!base || !name || name[0] != '/') {
        return name;
    }

    qemu_mutex_lock(&lock);

    /* Have we looked up this file before?  */
    if (g_hash_table_lookup_extended(hash, name, &key, &value)) {
        ret = value ? value : name;
    } else {
        char *save = g_strdup(name);
        char *full = g_build_filename(base, name, NULL);

        /* Look for the path; record the result, pass or fail.  */
        if (access(full, F_OK) == 0 || path_is_strict_root_prefix(name)) {
            /* Exists.  */
            g_hash_table_insert(hash, save, full);
            ret = full;
        } else {
            /* Does not exist.  */
            g_free(full);
            g_hash_table_insert(hash, save, NULL);
            ret = name;
        }
    }

    qemu_mutex_unlock(&lock);
    return ret;
}

/*
 * Unlike path(), do not apply QEMU_LD_PREFIX's normal existence-based
 * fallback here.  This helper is for path-taking syscalls that historically
 * bypassed path(); when a prefix was explicitly marked strict, they must make
 * the same root-local decision as open/stat/access.
 */
const char *path_forced(const char *name)
{
    if (!name || !path_is_strict_root_prefix(name)) {
        return name;
    }

    return path(name);
}
