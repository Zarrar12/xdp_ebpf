
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <stdint.h>
#include <iproute2/bpf_elf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/kernel.h>
// #include <bpf/bpf.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include "./libbpf/src/bpf_helpers.h"
// #include <bpf/bpf_helpers.h>

#ifndef lock_xadd
# define lock_xadd(ptr, val)              \
        ((void)__sync_fetch_and_add(ptr, val))
#endif

#ifndef __section
# define __section(NAME)                  \
	__attribute__((section(NAME), used))
#endif

#ifndef __inline
# define __inline                         \
        inline __attribute__((always_inline))
#endif

#ifndef BPF_FUNC
# define BPF_FUNC(NAME, ...)              \
        (*NAME)(__VA_ARGS__) = (void *)BPF_FUNC_##NAME
#endif

// #define SEC(NAME) __attribute__((section(NAME), used))

// static void *BPF_FUNC(map_lookup_elem, void *map, const void *key);
// static void *BPF_FUNC(map_update_elem, void *map, const void *key, const void *value, unsigned long flags);

// struct bpf_elf_map cnt_map __section("maps") = {
//  	.type           = BPF_MAP_TYPE_PERCPU_ARRAY,
//  	.size_key       = sizeof(uint32_t),
//  	.size_value     = sizeof(uint32_t),
//  	.pinning        = PIN_GLOBAL_NS,
//  	.max_elem       = 6,
// };

struct bpf_map_def SEC("maps") cnt_map = {
	.type        = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u32),
	.max_entries = 6,
};

// struct bpf_elf_map validPorts __section("maps") = {
// 	.type           = BPF_MAP_TYPE_PERCPU_ARRAY,
// 	.size_key       = sizeof(uint32_t),
// 	.size_value     = sizeof(uint32_t),
// 	.pinning        = PIN_GLOBAL_NS,
// 	.max_elem       = 4,
// };

struct bpf_map_def SEC("maps") validPorts = {
	.type        = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u32),
	.max_entries = 4,
};

struct bpf_map_def SEC("maps") newTable = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") scratchPad = {
	.type        = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u32),
	.max_entries = 1,
};


SEC("xdpMain")
int udpDropper(struct xdp_md *ctx) {
	unsigned int sigUdp = 0, portKey0 = 0, portKey1 = 1, portKey2 = 2, portKey3 = 3, swapped = 0;
	unsigned int *check, *almUdp, alarm = 1; //*almUdp, alarm = 1
	unsigned long int chk = 0;
	void *data = (void *)(unsigned long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	struct iphdr *ip = (struct iphdr*) ((char*)eth + sizeof(struct ethhdr));
	struct udphdr *udp = (struct udphdr*) ((char*)ip + sizeof(struct iphdr));

	if ((data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr)) > data_end)
        return 0;
	
	// Handle only IP packets
	if (eth->h_proto != __constant_htons(ETH_P_IP))
		return XDP_PASS;
       // return XDP_DROP;

	// Check the packet for payload
	if (ip + 1 >= (struct iphdr*) data_end)
		return XDP_PASS;
	
	if ((ip->ihl) < 5)
	        return XDP_PASS;
       
	// chk = bpf_map_update_elem(&scratchPad, &sigUdp, &portKey3, BPF_ANY);
	// if (chk)
	// 	return -1;
	// almUdp = map_lookup_elem(&cnt_map, &sigUdp);
	almUdp = bpf_map_lookup_elem(&cnt_map, &sigUdp);
	if (!almUdp)
		return -1;

	if (*almUdp == alarm) {
		// This is for UDP alarm
		if (ip->protocol == IPPROTO_UDP) {
			// network to host order
			swapped = ((udp->dest>>24)&0x000000ff) | ((udp->dest>>8)&0x0000ff00) | ((udp->dest<<8)&0x00ff0000) | ((udp->dest<<24)&0xff000000);
			swapped = (swapped) >> 16;
			// check = map_update_elem(&scratchPad, &sigUdp, &swapped, BPF_ANY);
			chk = bpf_map_update_elem(&scratchPad, &sigUdp, &swapped, BPF_ANY);
			if (chk)
				return -1;

			// check whether the packet is for the port
			// on which service is running.
			// check = map_lookup_elem(&validPorts, &portKey0);
			check = bpf_map_lookup_elem(&validPorts, &portKey0);
			if (!check)
				return -1;
			if (swapped == *check)
				return XDP_PASS;
			
			// check = map_lookup_elem(&validPorts, &portKey1);
			check = bpf_map_lookup_elem(&validPorts, &portKey1);
			if (!check)
				return -1;
			if (swapped == *check)
				return XDP_PASS;
			
			// check = map_lookup_elem(&validPorts, &portKey2);
			check = bpf_map_lookup_elem(&validPorts, &portKey2);
			if (!check)
				return -1;
			if (swapped == *check)
				return XDP_PASS;
			
			// check = map_lookup_elem(&validPorts, &portKey3);
			check = bpf_map_lookup_elem(&validPorts, &portKey3);
			if (!check)
				return -1;
			if (swapped == *check)
				return XDP_PASS;
			
			return XDP_DROP;
		}
		
	}
	
	bpf_tail_call(ctx, &newTable, 0);
	// When ther is no catch or the above tail call fails
	return XDP_PASS;
}

// SEC("tcpXdp")
SEC("xdp_1")
int tcpDropper(struct xdp_md *ctx) {
	unsigned int sigTcp = 5;
	unsigned int *almTcp, alarm = 1;
	void *data = (void *)(unsigned long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	struct iphdr *ip = (struct iphdr*) ((char*)eth + sizeof(struct ethhdr));
	// struct tcphdr *tcp = (struct tcphdr*) ((char*)ip + sizeof(struct iphdr));

	if ((data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)) > data_end)
        return 0;
	
	// Handle only IP packets
	if (eth->h_proto != __constant_htons(ETH_P_IP))
       return XDP_DROP;

	// Check the packet for payload
	// if ((char*)ip + (ip->ihl * 4) >= data_end)
	if ((char*)ip + sizeof(struct iphdr) >= (char*)data_end)
		return XDP_DROP;
	
	// Check for the minimum IP header length
	if (ip->ihl < 5)
		return XDP_PASS;
       
	// almTcp = map_lookup_elem(&cnt_map, &sigTcp);
	almTcp = bpf_map_lookup_elem(&cnt_map, &sigTcp);
	if (!almTcp)
		return -1;

	if (*almTcp == alarm) {
		// This is for TCP alarm
		if (ip->protocol == IPPROTO_TCP) {
			// if (tcp->syn == 1) {
				return XDP_DROP;
			// }
		}
	}
	// When ther is no catch
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
