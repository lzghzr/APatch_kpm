/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 * Copyright (C) 2024 lzghzr. All Rights Reserved.
 */
#ifndef __CF_UTILS_H
#define __CF_UTILS_H

#define logkm(fmt, ...) printk("cgroupv2_freeze: " fmt, ##__VA_ARGS__)

struct struct_offset {
  int16_t cgroup_flags;
  int16_t css_set_dfl_cgrp;
  int16_t freezer_state;
  int16_t seq_file_private;
  int16_t signal_struct_flags;
  int16_t signal_struct_group_exit_task;
  int16_t subprocess_info_argv;
  int16_t subprocess_info_path;
  int16_t task_struct_css_set;
  int16_t task_struct_flags;
  int16_t task_struct_jobctl;
  int16_t task_struct_signal;
  int16_t task_struct_state;
};

#endif /* __CF_UTILS_H */
