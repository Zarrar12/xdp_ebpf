
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <stdint.h>
#include <iproute2/bpf_elf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>


#define SEC(NAME) __attribute__((section(NAME), used))
#define MY_IP	"192.168.2.101"

SEC("xdp")
int dropper(struct xdp_md *ctx) {

	int mapFd;
	int packs;
	unsigned int dir = 0;
	unsigned int ipsize = 0;
	void *data = (void *)(unsigned long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	
	mapFd = bpf_obj_get("/sys/fs/bpf/ip/globals/cnt_map");

	struct ethhdr *eth = data;
	ipsize = sizeof(struct ethhdr);
	
	struct iphdr *ip = eth + 1;	//Jump over the ethernet header

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

	
	packs = bpf_map_lookup_elem(&mapFd, &dir);
	if (packs == 20) {
		if ((ip->protocol == IPPROTO_UDP) && (ip->saddr == MY_IP))
			return XDP_DROP;
	}
	// When ther is no catch
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
