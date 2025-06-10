// task_pid
static inline pid_t task_pid(struct task_struct* task) {
    pid_t pid = *(pid_t*)((uintptr_t)task + struct_offset.task_struct_pid);
    return pid;
}
// task_tgid
static inline pid_t task_tgid(struct task_struct* task) {
    pid_t tgid = *(pid_t*)((uintptr_t)task + struct_offset.task_struct_tgid);
    return tgid;
}
// task_jobctl
static inline unsigned long task_jobctl(struct task_struct* task) {
    unsigned long jobctl = *(unsigned long*)((uintptr_t)task + struct_offset.task_struct_jobctl);
    return jobctl;
}
// binder_proc_is_frozen
static inline bool binder_proc_is_frozen(struct binder_proc* proc) {
    bool is_frozen = *(bool*)((uintptr_t)proc + struct_offset.binder_proc_is_frozen);
    return is_frozen;
}
// binder_proc_alloc
static inline struct binder_alloc* binder_proc_alloc(struct binder_proc* proc) {
    struct binder_alloc* alloc = (struct binder_alloc*)((uintptr_t)proc + struct_offset.binder_proc_alloc);
    return alloc;
}
//  binder_proc_inner_lock
static inline spinlock_t* binder_proc_inner_lock(struct binder_proc* proc) {
    spinlock_t* inner_lock = (spinlock_t*)((uintptr_t)proc + struct_offset.binder_proc_inner_lock);
    return inner_lock;
}
//  binder_proc_outstanding_txns
static inline int* binder_proc_outstanding_txns(struct binder_proc* proc) {
    int* outstanding_txns = (int*)((uintptr_t)proc + struct_offset.binder_proc_outstanding_txns);
    return outstanding_txns;
}
// binder_alloc_buffer
static inline void __user* binder_alloc_buffer(struct binder_alloc* alloc) {
    void __user* buffer = *(void __user**)((uintptr_t)alloc + struct_offset.binder_alloc_buffer);
    return buffer;
}
// binder_alloc_free_async_space
static inline size_t binder_alloc_free_async_space(struct binder_alloc* alloc) {
    size_t free_async_space = *(size_t*)((uintptr_t)alloc + struct_offset.binder_alloc_free_async_space);
    return free_async_space;
}
// binder_alloc_buffer_size
static inline size_t binder_alloc_buffer_size(struct binder_alloc* alloc) {
    size_t buffer_size = *(size_t*)((uintptr_t)alloc + struct_offset.binder_alloc_buffer_size);
    return buffer_size;
}
// binder_transaction_from
static inline struct binder_thread* binder_transaction_from(struct binder_transaction* t) {
    struct binder_thread* from = *(struct binder_thread**)((uintptr_t)t + struct_offset.binder_transaction_from);
    return from;
}
// binder_transaction_to_proc
static inline struct binder_proc* binder_transaction_to_proc(struct binder_transaction* t) {
    struct binder_proc* to_proc = *(struct binder_proc**)((uintptr_t)t + struct_offset.binder_transaction_to_proc);
    return to_proc;
}
// binder_transaction_buffer
static inline struct binder_buffer* binder_transaction_buffer(struct binder_transaction* t) {
    struct binder_buffer* buffer = *(struct binder_buffer**)((uintptr_t)t + struct_offset.binder_transaction_buffer);
    return buffer;
}
// binder_transaction_code
static inline unsigned int binder_transaction_code(struct binder_transaction* t) {
    unsigned int code = *(unsigned int*)((uintptr_t)t + struct_offset.binder_transaction_code);
    return code;
}
// binder_transaction_flags
static inline unsigned int binder_transaction_flags(struct binder_transaction* t) {
    unsigned int flags = *(unsigned int*)((uintptr_t)t + struct_offset.binder_transaction_flags);
    return flags;
}
// binder_node_lock_ptr
static inline spinlock_t* binder_node_lock_ptr(struct binder_node* node) {
    spinlock_t* lock = (spinlock_t*)((uintptr_t)node + struct_offset.binder_node_lock);
    return lock;
}
// binder_node_ptr
static inline binder_uintptr_t binder_node_ptr(struct binder_node* node) {
    binder_uintptr_t ptr = *(binder_uintptr_t*)((uintptr_t)node + struct_offset.binder_node_ptr);
    return ptr;
}
// binder_node_cookie
static inline binder_uintptr_t binder_node_cookie(struct binder_node* node) {
    binder_uintptr_t cookie = *(binder_uintptr_t*)((uintptr_t)node + struct_offset.binder_node_cookie);
    return cookie;
}
// binder_node_has_async_transaction
static inline bool binder_node_has_async_transaction(struct binder_node* node) {
    bool has_async_transaction = *(bool*)((uintptr_t)node + struct_offset.binder_node_has_async_transaction);
    return has_async_transaction;
}
// binder_node_async_todo
static inline struct list_head* binder_node_async_todo(struct binder_node* node) {
    struct list_head* async_todo = (struct list_head*)((uintptr_t)node + struct_offset.binder_node_async_todo);
    return async_todo;
}
