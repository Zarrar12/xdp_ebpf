#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <stdint.h>
#include <iproute2/bpf_elf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
// #include <uapi/linux/ip.h>
#include "uapi/linux/ip.h"
#include "libbpf/src/bpf.h"




#ifndef __section
# define __section(NAME)                  \
	__attribute__((section(NAME), used))
#endif

#ifndef __inline
# define __inline                         \
        inline __attribute__((always_inline))
#endif

#ifndef lock_xadd
# define lock_xadd(ptr, val)              \
        ((void)__sync_fetch_and_add(ptr, val))
#endif

#ifndef BPF_FUNC
# define BPF_FUNC(NAME, ...)              \
        (*NAME)(__VA_ARGS__) = (void *)BPF_FUNC_##NAME
#endif

#define MY_IP	0xC0A80265

static void *BPF_FUNC(map_lookup_elem, void *map, const void *key);

struct bpf_elf_map cnt_map __section("maps") = {
	.type           = BPF_MAP_TYPE_ARRAY,
	.size_key       = sizeof(uint32_t),
	.size_value     = sizeof(uint32_t),
	.pinning        = PIN_GLOBAL_NS,
	.max_elem       = 1,
};

// __section("ingress")
// static __inline int account_data(struct __sk_buff *ctx, uint32_t dir)
// {
// 	uint32_t *packs;
// 	static uint32_t skbCnt = 0;
// 	struct iphdr *ip;
	

// 	// ip = ip_hdr(ctx);
// 	ip = (struct iphdr*) ctx;
// 	// if ((ip->protocol == IPPROTO_UDP) && (ip->saddr == MY_IP)) {
// 	// 	skbCnt++;
// 		packs = map_lookup_elem(&cnt_map, &dir);
// 		if (packs)
// 			lock_xadd(packs, 1);
// 			// lock_xadd(packs, skbCnt);
// 	// }
// 	return TC_ACT_OK;
// }

// __section("ingress")
// int tc_ingress(struct __sk_buff *skb)
// {
// 	return account_data(skb, 0);
// }

__section("ingress")
int tc_ingress(struct __sk_buff *skb)
{
        unsigned int key = 0, *val;

        val = map_lookup_elem(&cnt_map, &key);
        if (val)
                lock_xadd(val, 1);

		return TC_ACT_OK;
}

char __license[] __section("license") = "GPL";
