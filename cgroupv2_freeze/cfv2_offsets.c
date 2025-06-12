// task_state_ptr
static inline volatile long* task_state_ptr(struct task_struct* task) {
  volatile long* state = (volatile long*)((uintptr_t)task + struct_offset.task_struct_state);
  return state;
}
// task_flags
static inline unsigned int task_flags(struct task_struct* task) {
  unsigned int flags = *(unsigned int*)((uintptr_t)task + struct_offset.task_struct_flags);
  return flags;
}
// task_flags_ptr
static inline unsigned int* task_flags_ptr(struct task_struct* task) {
  unsigned int* flags = (unsigned int*)((uintptr_t)task + struct_offset.task_struct_flags);
  return flags;
}
// task_jobctl
static inline unsigned long task_jobctl(struct task_struct* task) {
  unsigned long jobctl = *(unsigned long*)((uintptr_t)task + struct_offset.task_struct_jobctl);
  return jobctl;
}
// task_jobctl_ptr
static inline unsigned long* task_jobctl_ptr(struct task_struct* task) {
  unsigned long* jobctl = (unsigned long*)((uintptr_t)task + struct_offset.task_struct_jobctl);
  return jobctl;
}
// task_signal
static inline struct signal_struct* task_signal(struct task_struct* task) {
  struct signal_struct* signal = *(struct signal_struct**)((uintptr_t)task + struct_offset.task_struct_signal);
  return signal;
}
// signal_group_exit_task
static inline struct task_struct* signal_group_exit_task(struct signal_struct* sig) {
  struct task_struct* group_exit_task = *(struct task_struct**)((uintptr_t)sig + struct_offset.signal_struct_group_exit_task);
  return group_exit_task;
}
// signal_flags
static inline unsigned int signal_flags(struct signal_struct* sig) {
  unsigned int flags = *(unsigned int*)((uintptr_t)sig + struct_offset.signal_struct_flags);
  return flags;
}
// seq_file_private
static inline struct kernfs_open_file* seq_file_private(struct seq_file* seq) {
  struct kernfs_open_file* private = *(struct kernfs_open_file**)((uintptr_t)seq + struct_offset.seq_file_private);
  return private;
}
// cgroup_flags_ptr
static inline unsigned long* cgroup_flags_ptr(struct cgroup* cgrp) {
  unsigned long* flags = (unsigned long*)((uintptr_t)cgrp + struct_offset.cgroup_flags);
  return flags;
}
// css_set_dfl_cgrp
static inline struct cgroup* css_set_dfl_cgrp(struct css_set* cset) {
  struct cgroup* cgrp = *(struct cgroup**)((uintptr_t)cset + struct_offset.css_set_dfl_cgrp);
  return cgrp;
}
// subprocess_info_argv
static inline char** subprocess_info_argv(struct subprocess_info* sub_info) {
  char** argv = *(char***)((uintptr_t)sub_info + struct_offset.subprocess_info_argv);
  return argv;
}
