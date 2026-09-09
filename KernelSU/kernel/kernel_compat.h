#ifndef __KSU_H_KERNEL_COMPAT
#define __KSU_H_KERNEL_COMPAT

#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/version.h>

/*
 * The *_nofault() uaccess family only exists on 5.8+. On older kernels,
 * probe_kernel_read()/probe_kernel_write() provide the same fault-free
 * semantics with compatible success/failure truthiness (0 on success).
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
#ifndef copy_to_kernel_nofault
#define copy_to_kernel_nofault(dst, src, len) probe_kernel_write(dst, src, len)
#endif
#ifndef copy_from_user_nofault
#define copy_from_user_nofault(to, from, n) probe_kernel_read(to, from, n)
#endif
#ifndef copy_to_user_nofault
#define copy_to_user_nofault(to, from, n) probe_kernel_write(to, from, n)
#endif
#endif

/*
 * ksu_copy_from_user_retry
 * try nofault copy first, if it fails, try with plain
 * paramters are the same as copy_from_user
 * 0 = success
 */
static long ksu_copy_from_user_retry(void *to, const void __user *from,
                                     unsigned long count)
{
    long ret = copy_from_user_nofault(to, from, count);
    if (likely(!ret))
        return ret;

    // we faulted! fallback to slow path
    return copy_from_user(to, from, count);
}

#endif
