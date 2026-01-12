#ifndef __RITMA_BPF_ENDIAN_H
#define __RITMA_BPF_ENDIAN_H

#ifndef __u16
typedef unsigned short __u16;
#endif

#ifndef __u32
typedef unsigned int __u32;
#endif

static __inline __u16 bpf_htons(__u16 x) { return __builtin_bswap16(x); }
static __inline __u16 bpf_ntohs(__u16 x) { return __builtin_bswap16(x); }
static __inline __u32 bpf_htonl(__u32 x) { return __builtin_bswap32(x); }
static __inline __u32 bpf_ntohl(__u32 x) { return __builtin_bswap32(x); }

#endif
