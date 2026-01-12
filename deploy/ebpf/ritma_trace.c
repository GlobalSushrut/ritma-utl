// SPDX-License-Identifier: GPL-2.0

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2
#define AF_INET6 10

typedef unsigned short sa_family_t;

struct in_addr {
    __u32 s_addr;
};

struct in6_addr {
    union {
        __u8 u6_addr8[16];
        __u16 u6_addr16[8];
        __u32 u6_addr32[4];
    } in6_u;
};

struct sockaddr {
    sa_family_t sa_family;
    __u8 sa_data[14];
};

struct sockaddr_in {
    sa_family_t sin_family;
    __u16 sin_port;
    struct in_addr sin_addr;
    __u8 __pad[8];
};

struct sockaddr_in6 {
    sa_family_t sin6_family;
    __u16 sin6_port;
    __u32 sin6_flowinfo;
    struct in6_addr sin6_addr;
    __u32 sin6_scope_id;
};

struct iovec {
    const void *iov_base;
    __u64 iov_len;
};

struct msghdr {
    void *msg_name;
    __u32 msg_namelen;
    __u32 __pad1;
    struct iovec *msg_iov;
    __u64 msg_iovlen;
    void *msg_control;
    __u64 msg_controllen;
    __u32 msg_flags;
    __u32 __pad2;
};

#define RITMA_EVENT_EXECVE  1
#define RITMA_EVENT_OPENAT  2
#define RITMA_EVENT_CONNECT 3

#define RITMA_EVENT_DNS     4

struct ritma_event {
    __u32 kind;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u64 cgroup_id;
    union {
        struct {
            __u8 comm[16];
        } execve;
        struct {
            __u8 path[80];
        } openat;
        struct {
            __u16 family;
            __u16 dport;
            __u8 daddr[16];
        } connect;
        struct {
            __u16 family;
            __u16 dport;
            __u8 daddr[16];
            __u32 len;
            __u8 payload[96];
        } dns;
        __u8 _pad[128];
    } data;
};

struct bpf_map_def SEC("maps") events = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .key_size = 0,
    .value_size = 0,
    .max_entries = 1 << 24,
    .map_flags = 0,
};

struct trace_event_raw_sys_enter {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    __s64 id;
    __u64 args[6];
};

SEC("tracepoint/syscalls/sys_enter_execve")
int ritma_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct ritma_event *e;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->kind = RITMA_EVENT_EXECVE;
    e->pid = (__u32)(pid_tgid >> 32);
    e->ppid = 0;
    e->uid = (__u32)(uid_gid & 0xFFFFFFFF);
    e->gid = (__u32)(uid_gid >> 32);
    e->cgroup_id = bpf_get_current_cgroup_id();

    __builtin_memset(&e->data, 0, sizeof(e->data));
    bpf_get_current_comm(&e->data.execve.comm, sizeof(e->data.execve.comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int ritma_sendmsg(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    const struct msghdr *msg = (const struct msghdr *)ctx->args[1];

    if (!msg) {
        return 0;
    }

    struct msghdr mh = {};
    bpf_probe_read_user(&mh, sizeof(mh), msg);

    if (!mh.msg_iov || mh.msg_iovlen == 0) {
        return 0;
    }

    struct iovec iov0 = {};
    bpf_probe_read_user(&iov0, sizeof(iov0), mh.msg_iov);

    const void *buf = iov0.iov_base;
    __u64 len = iov0.iov_len;
    const struct sockaddr *addr = (const struct sockaddr *)mh.msg_name;

    __u16 family = 0;
    __u16 dport = 0;
    if (addr) {
        bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
        if (family == AF_INET) {
            struct sockaddr_in sin = {};
            bpf_probe_read_user(&sin, sizeof(sin), addr);
            dport = bpf_ntohs(sin.sin_port);
        } else if (family == AF_INET6) {
            struct sockaddr_in6 sin6 = {};
            bpf_probe_read_user(&sin6, sizeof(sin6), addr);
            dport = bpf_ntohs(sin6.sin6_port);
        }
    }

    __u8 hdr[12] = {};
    if (len >= 12 && buf) {
        bpf_probe_read_user(&hdr[0], sizeof(hdr), buf);
    }

    __u16 flags = ((__u16)hdr[2] << 8) | (__u16)hdr[3];
    __u16 qdcount = ((__u16)hdr[4] << 8) | (__u16)hdr[5];
    __u16 qr = (flags >> 15) & 1;

    int looks_like_dns = (len >= 12) && (qr == 0) && (qdcount > 0) && (qdcount <= 4);
    if (!(dport == 53 || looks_like_dns)) {
        return 0;
    }

    if (dport == 0 && looks_like_dns) {
        dport = 53;
    }

    struct ritma_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->kind = RITMA_EVENT_DNS;
    e->pid = (__u32)(pid_tgid >> 32);
    e->ppid = 0;
    e->uid = (__u32)(uid_gid & 0xFFFFFFFF);
    e->gid = (__u32)(uid_gid >> 32);
    e->cgroup_id = bpf_get_current_cgroup_id();

    __builtin_memset(&e->data, 0, sizeof(e->data));
    e->data.dns.family = family;
    e->data.dns.dport = dport;

    if (addr) {
        if (family == AF_INET) {
            struct sockaddr_in sin = {};
            bpf_probe_read_user(&sin, sizeof(sin), addr);
            __builtin_memcpy(&e->data.dns.daddr[0], &sin.sin_addr.s_addr, 4);
        } else if (family == AF_INET6) {
            struct sockaddr_in6 sin6 = {};
            bpf_probe_read_user(&sin6, sizeof(sin6), addr);
            __builtin_memcpy(&e->data.dns.daddr[0], &sin6.sin6_addr.in6_u.u6_addr8, 16);
        }
    }

    __u32 max_len = sizeof(e->data.dns.payload);
    __u32 cap = 0;
    if (buf) {
        cap = (__u32)len;
        if (cap > max_len) {
            cap = max_len;
        }
        if (cap > 0) {
            bpf_probe_read_user(&e->data.dns.payload[0], max_len, buf);
        }
    }
    e->data.dns.len = cap;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int ritma_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct ritma_event *e;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    const char *filename = (const char *)ctx->args[1];

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->kind = RITMA_EVENT_OPENAT;
    e->pid = (__u32)(pid_tgid >> 32);
    e->ppid = 0;
    e->uid = (__u32)(uid_gid & 0xFFFFFFFF);
    e->gid = (__u32)(uid_gid >> 32);
    e->cgroup_id = bpf_get_current_cgroup_id();

    __builtin_memset(&e->data, 0, sizeof(e->data));
    bpf_probe_read_user_str(e->data.openat.path, sizeof(e->data.openat.path), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int ritma_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct ritma_event *e;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    const struct sockaddr *addr = (const struct sockaddr *)ctx->args[1];

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->kind = RITMA_EVENT_CONNECT;
    e->pid = (__u32)(pid_tgid >> 32);
    e->ppid = 0;
    e->uid = (__u32)(uid_gid & 0xFFFFFFFF);
    e->gid = (__u32)(uid_gid >> 32);
    e->cgroup_id = bpf_get_current_cgroup_id();

    __builtin_memset(&e->data, 0, sizeof(e->data));

    __u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
    e->data.connect.family = family;

    if (family == AF_INET) {
        struct sockaddr_in sin = {};
        bpf_probe_read_user(&sin, sizeof(sin), addr);
        e->data.connect.dport = bpf_ntohs(sin.sin_port);
        __builtin_memcpy(&e->data.connect.daddr[0], &sin.sin_addr.s_addr, 4);
    } else if (family == AF_INET6) {
        struct sockaddr_in6 sin6 = {};
        bpf_probe_read_user(&sin6, sizeof(sin6), addr);
        e->data.connect.dport = bpf_ntohs(sin6.sin6_port);
        __builtin_memcpy(&e->data.connect.daddr[0], &sin6.sin6_addr.in6_u.u6_addr8, 16);
    } else {
        e->data.connect.dport = 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int ritma_sendto(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    const void *buf = (const void *)ctx->args[1];
    __u64 len = ctx->args[2];
    const struct sockaddr *addr = (const struct sockaddr *)ctx->args[4];

    __u16 family = 0;
    __u16 dport = 0;
    if (addr) {
        bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
        if (family == AF_INET) {
            struct sockaddr_in sin = {};
            bpf_probe_read_user(&sin, sizeof(sin), addr);
            dport = bpf_ntohs(sin.sin_port);
        } else if (family == AF_INET6) {
            struct sockaddr_in6 sin6 = {};
            bpf_probe_read_user(&sin6, sizeof(sin6), addr);
            dport = bpf_ntohs(sin6.sin6_port);
        }
    }

    __u8 hdr[12] = {};
    if (len >= 12 && buf) {
        bpf_probe_read_user(&hdr[0], sizeof(hdr), buf);
    }

    __u16 flags = ((__u16)hdr[2] << 8) | (__u16)hdr[3];
    __u16 qdcount = ((__u16)hdr[4] << 8) | (__u16)hdr[5];
    __u16 qr = (flags >> 15) & 1;

    int looks_like_dns = (len >= 12) && (qr == 0) && (qdcount > 0) && (qdcount <= 4);
    if (!(dport == 53 || looks_like_dns)) {
        return 0;
    }

    if (dport == 0 && looks_like_dns) {
        dport = 53;
    }

    struct ritma_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->kind = RITMA_EVENT_DNS;
    e->pid = (__u32)(pid_tgid >> 32);
    e->ppid = 0;
    e->uid = (__u32)(uid_gid & 0xFFFFFFFF);
    e->gid = (__u32)(uid_gid >> 32);
    e->cgroup_id = bpf_get_current_cgroup_id();

    __builtin_memset(&e->data, 0, sizeof(e->data));
    e->data.dns.family = family;
    e->data.dns.dport = dport;

    if (addr) {
        if (family == AF_INET) {
            struct sockaddr_in sin = {};
            bpf_probe_read_user(&sin, sizeof(sin), addr);
            __builtin_memcpy(&e->data.dns.daddr[0], &sin.sin_addr.s_addr, 4);
        } else if (family == AF_INET6) {
            struct sockaddr_in6 sin6 = {};
            bpf_probe_read_user(&sin6, sizeof(sin6), addr);
            __builtin_memcpy(&e->data.dns.daddr[0], &sin6.sin6_addr.in6_u.u6_addr8, 16);
        }
    }

    __u32 max_len = sizeof(e->data.dns.payload);
    __u32 cap = 0;
    if (buf) {
        cap = (__u32)len;
        if (cap > max_len) {
            cap = max_len;
        }
        if (cap > 0) {
            bpf_probe_read_user(&e->data.dns.payload[0], max_len, buf);
        }
    }
    e->data.dns.len = cap;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
