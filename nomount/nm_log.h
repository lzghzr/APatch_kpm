/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __NM_LOG_H
#define __NM_LOG_H

#include <linux/printk.h>

#define nm_log_info(fmt, ...) pr_info("NoMount: " fmt, ##__VA_ARGS__)
#define nm_log_error(fmt, ...) pr_err("NoMount: " fmt, ##__VA_ARGS__)

#endif
