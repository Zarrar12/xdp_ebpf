
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <stdint.h>
#include <iproute2/bpf_elf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include "libbpf/src/bpf.h"
// #include "Torvalds_libbpf.h"

#ifndef lock_xadd
# define lock_xadd(ptr, val)              \
        ((void)__sync_fetch_and_add(ptr, val))
#endif

#ifndef __inline
# define __inline                         \
        inline __attribute__((always_inline))
#endif

#ifndef BPF_FUNC
# define BPF_FUNC(NAME, ...)              \
        (*NAME)(__VA_ARGS__) = (void *)BPF_FUNC_##NAME
#endif

#define SEC(NAME) __attribute__((section(NAME), used))
#define MY_IP	0xC0A80265

static void *BPF_FUNC(map_lookup_elem, void *map, const void *key);

// struct bpf_elf_map cnt_map __section("maps") = {
struct bpf_elf_map cnt_map = {
	.type           = BPF_MAP_TYPE_ARRAY,
	.size_key       = sizeof(uint32_t),
	.size_value     = sizeof(uint32_t),
	.pinning        = PIN_GLOBAL_NS,
	.max_elem       = 1,
};

SEC("xdp")
int dropper(struct xdp_md *ctx) {

	int skbCnt = 11;
	int mapFd;
	unsigned int *packs;
	unsigned int dir = 0;
	
	void *data = (void *)(unsigned long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	
	// mapFd = bpf_object__open("/sys/fs/bpf/ip/globals/cnt_map");
	// mapFd = bpf_obj_get("/sys/fs/bpf/ip/globals/cnt_map");
	// mapFd = bpf(BPF_OBJ_GET, &cnt_map);

	mapFd = bpf_map__fd(&cnt_map);

	struct ethhdr *eth = data;
	
	// struct iphdr *ip = eth + 1;	//Jump over the ethernet header
	struct iphdr *ip = (struct iphdr*)((char*)eth + sizeof(struct ethhdr));	//Jump over the ethernet header

	if ((data + sizeof(struct ethhdr) + sizeof(struct iphdr)) > data_end)
        return 0;

	// Handle only IP packets
	if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_DROP;

	// Check the packet for payload
	if (ip + 1 >= (struct iphdr*) data_end)
        return XDP_PASS;

	if ((ip->ihl) < 5)
        return XDP_DROP;

	// packs = &skbCnt;
	packs = map_lookup_elem(&cnt_map, &dir);
	if (*packs == skbCnt) {
	if (mapFd)	
		if ((ip->protocol == IPPROTO_UDP) && (ip->saddr == MY_IP))
			return XDP_DROP;
	}
	// When ther is no catch
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
