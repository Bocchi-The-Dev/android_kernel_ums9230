#include <linux/cache.h>
#include <linux/compiler.h>
#include <linux/compat.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/ptrace.h>
#include <linux/sched/task_stack.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <asm/current.h>

#include "klog.h" // IWYU pragma: keep
#include "feature/manual_hook.h"
#include "feature/sucompat.h"
#include "policy/allowlist.h"
#include "policy/app_profile.h"
#include "runtime/ksud.h"

#ifdef CONFIG_KSU_MANUAL_HOOK

#define SU_PATH "/system/bin/su"
#define SH_PATH "/system/bin/sh"

// Mirror of fs/exec.c's struct user_arg_ptr (also redefined in
// runtime/ksud_integration.c and sulog/event.c). The manually-patched
// execve call site passes a pointer to its local copy as void *argv.
struct user_arg_ptr {
#ifdef CONFIG_COMPAT
    bool is_compat;
#endif
    union {
        const char __user *const __user *native;
#ifdef CONFIG_COMPAT
        const compat_uptr_t __user *compat;
#endif
    } ptr;
};

bool ksu_execveat_hook __read_mostly = true;
bool ksu_vfs_read_hook __read_mostly = true;
bool ksu_input_hook __read_mostly = true;

static void __user *manual_hook_stack_buffer(const void *d, size_t len)
{
    // To avoid having to mmap a page in userspace, just write below the stack
    // pointer.
    char __user *p = (void __user *)current_user_stack_pointer() - len;

    return copy_to_user(p, d, len) ? NULL : p;
}

static char __user *manual_hook_sh_path(void)
{
    static const char sh_path[] = SH_PATH;

    return manual_hook_stack_buffer(sh_path, sizeof(sh_path));
}

// ksud execve handling for the manual probe: init second-stage setup and
// first-zygote preparation, same logic the dispatcher path uses.
int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags)
{
    struct filename *filename;

    (void)fd;
    (void)envp;
    (void)flags;

    if (unlikely(!filename_ptr))
        return 0;

    filename = *filename_ptr;
    // do_execve_file() passes a NULL filename, don't dereference it.
    if (!filename || IS_ERR(filename))
        return 0;

    ksu_handle_execveat_ksud(filename->name, (struct user_arg_ptr *)argv);
    return 0;
}

// sucompat execve handling for the manual probe: permitted processes
// executing /system/bin/su are redirected to ksud and granted root.
int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags)
{
    static const char su[] = SU_PATH;
    struct filename *filename;
    int ret;

    (void)fd;
    (void)argv;
    (void)envp;
    (void)flags;

    if (!ksu_su_compat_enabled)
        return 0;

    if (unlikely(!filename_ptr))
        return 0;

    filename = *filename_ptr;
    if (!filename || IS_ERR(filename))
        return 0;

    if (likely(memcmp(filename->name, su, sizeof(su))))
        return 0;

    if (!ksu_is_allow_uid_for_current(current_uid().val))
        return 0;

    pr_info("manual_hook: do_execveat_common su found\n");
    // filename->name points into a PATH_MAX-sized getname buffer, so
    // overwriting it with the shorter KSUD_PATH is safe.
    memcpy((void *)filename->name, KSUD_PATH, sizeof(KSUD_PATH));

    ret = escape_with_root_profile();
    if (ret)
        pr_err("manual_hook: escape_with_root_profile failed: %d\n", ret);

    return 0;
}

// sucompat faccessat handling for the manual probe: permitted processes
// checking /system/bin/su are pointed at sh instead.
int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode, int *flags)
{
    static const char su[] = SU_PATH;
    char path[sizeof(su) + 1];

    (void)dfd;
    (void)mode;
    (void)flags;

    if (unlikely(!filename_user))
        return 0;

    if (!ksu_is_allow_uid_for_current(current_uid().val))
        return 0;

    memset(path, 0, sizeof(path));
    strncpy_from_user_nofault(path, *filename_user, sizeof(path));

    if (unlikely(!memcmp(path, su, sizeof(su)))) {
        pr_info("manual_hook: faccessat su->sh!\n");
        *filename_user = manual_hook_sh_path();
    }

    return 0;
}

// sucompat stat handling for the manual probe: same su->sh redirection.
int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
    static const char su[] = SU_PATH;
    char path[sizeof(su) + 1];

    (void)dfd;
    (void)flags;

    if (unlikely(!filename_user))
        return 0;

    if (!ksu_is_allow_uid_for_current(current_uid().val))
        return 0;

    memset(path, 0, sizeof(path));
    strncpy_from_user_nofault(path, *filename_user, sizeof(path));

    if (unlikely(!memcmp(path, su, sizeof(su)))) {
        pr_info("manual_hook: newfstatat su->sh!\n");
        *filename_user = manual_hook_sh_path();
    }

    return 0;
}

int ksu_handle_devpts(struct inode *inode)
{
    // The devpts hook historically retagged the pty inode with the KSU
    // devpts SID so that root shells could run `pm`. That SID plumbing
    // (ksu_devpts_sid) was removed in the v4 refactor, so there is nothing
    // left to do here. Keep the handler as a no-op so the manually-patched
    // devpts_get_priv() call site links and stays harmless.
    (void)inode;
    return 0;
}

#endif // CONFIG_KSU_MANUAL_HOOK
