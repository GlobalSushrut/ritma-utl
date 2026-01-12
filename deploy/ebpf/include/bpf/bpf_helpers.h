#ifndef __RITMA_BPF_HELPERS_H
#define __RITMA_BPF_HELPERS_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

typedef int __s32;
typedef long long __s64;

#define SEC(name) __attribute__((section(name), used))

#ifndef __always_inline
#define __always_inline __attribute__((always_inline))
#endif

#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name

struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
};

enum libbpf_pin_type {
    LIBBPF_PIN_NONE = 0,
    LIBBPF_PIN_BY_NAME = 1,
};

#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_MAP_TYPE_RINGBUF 27

#define BPF_FUNC_map_lookup_elem 1
#define BPF_FUNC_map_update_elem 2
#define BPF_FUNC_map_delete_elem 3
#define BPF_FUNC_get_current_pid_tgid 14
#define BPF_FUNC_get_current_uid_gid 15
#define BPF_FUNC_get_current_comm 16
#define BPF_FUNC_get_current_cgroup_id 80
#define BPF_FUNC_probe_read_user 112
#define BPF_FUNC_probe_read_user_str 114
#define BPF_FUNC_ringbuf_reserve 131
#define BPF_FUNC_ringbuf_submit 132

static __u64 (*bpf_get_current_pid_tgid)(void) =
    (void *)BPF_FUNC_get_current_pid_tgid;
static __u64 (*bpf_get_current_uid_gid)(void) =
    (void *)BPF_FUNC_get_current_uid_gid;
static __u64 (*bpf_get_current_cgroup_id)(void) =
    (void *)BPF_FUNC_get_current_cgroup_id;
static long (*bpf_get_current_comm)(void *buf, __u32 size) =
    (void *)BPF_FUNC_get_current_comm;
static long (*bpf_probe_read_user)(void *dst, __u32 size, const void *unsafe_ptr) =
    (void *)BPF_FUNC_probe_read_user;
static long (*bpf_probe_read_user_str)(void *dst, __u32 size, const void *unsafe_ptr) =
    (void *)BPF_FUNC_probe_read_user_str;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) =
    (void *)BPF_FUNC_ringbuf_reserve;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) =
    (void *)BPF_FUNC_ringbuf_submit;

static void *(*bpf_map_lookup_elem)(const void *map, const void *key) =
    (void *)BPF_FUNC_map_lookup_elem;

static long (*bpf_map_update_elem)(const void *map, const void *key, const void *value, __u64 flags) =
    (void *)BPF_FUNC_map_update_elem;

static long (*bpf_map_delete_elem)(const void *map, const void *key) =
    (void *)BPF_FUNC_map_delete_elem;

#endif
