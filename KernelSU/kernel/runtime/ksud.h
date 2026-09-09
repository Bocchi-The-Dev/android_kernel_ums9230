#ifndef __KSU_H_KSUD
#define __KSU_H_KSUD

#include <asm/syscall.h>
#include <linux/compiler.h>

#define KSUD_PATH "/data/adb/ksud"

void ksu_ksud_init();
void ksu_ksud_exit();

void ksu_execve_hook_ksud(const struct pt_regs *regs);
void ksu_execveat_hook_ksud(const struct pt_regs *regs);
void ksu_stop_input_hook_runtime(void);

// init.rc injection for the manual read probe (fs/read_write.c).
// Implemented in runtime/ksud_integration.c.
int ksu_handle_sys_read(unsigned int fd, char __user **buf_ptr, size_t *count_ptr);

#endif
