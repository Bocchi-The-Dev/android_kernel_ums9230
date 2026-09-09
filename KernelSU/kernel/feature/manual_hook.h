#ifndef __KSU_H_MANUAL_HOOK
#define __KSU_H_MANUAL_HOOK

#include <linux/cache.h>
#include <linux/compiler.h>
#include <linux/types.h>

struct filename;
struct inode;

#ifdef CONFIG_KSU_MANUAL_HOOK

// Hook-state flags, consulted by the manually-patched kernel call sites.
// They start as true and are cleared once the corresponding startup work
// (ksud execve handling, init.rc injection, input safe-mode detection)
// is done, mirroring the kprobe/tracepoint lifecycle.
extern bool ksu_execveat_hook __read_mostly;
extern bool ksu_vfs_read_hook __read_mostly;
extern bool ksu_input_hook __read_mostly;

struct filename;
struct inode;
struct user_arg_ptr;

// Implemented by runtime/ksud_integration.c, invoked from the manual
// execve probe with the already-resolved kernel path.
void ksu_handle_execveat_ksud(const char *path, struct user_arg_ptr *argv);

// Classic manual-hook handlers, implemented in feature/manual_hook.c.
// Signatures match the call sites in fs/exec.c, fs/open.c,
// fs/read_write.c (via ksud_integration.c), fs/stat.c, fs/devpts/inode.c
// and drivers/input/input.c.
int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags);
int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags);
int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode, int *flags);
int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags);
int ksu_handle_devpts(struct inode *inode);

#endif // CONFIG_KSU_MANUAL_HOOK

#endif
