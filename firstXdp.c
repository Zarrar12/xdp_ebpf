// #include <linux/bpf.h>

// #define SEC(NAME) __attribute__((section(NAME), used))


// SEC("xdp")
// int xdp_drop(struct xdp_md *ctx) {
//    return XDP_DROP;
// }

// char __license[] SEC("license") = "GPL";



#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#define SEC(NAME) __attribute__((section(NAME), used))
#define MY_IP	"192.168.2.101"

SEC("xdp")

int dropper(struct xdp_md *ctx) {

	unsigned int ipsize = 0;
	void *data = (void *)(unsigned long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	ipsize = sizeof(*eth);
	
	struct iphdr *ip = eth + 1;	//Jump over the ethernet header

	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return 0;

	// Handle only IP packets
	if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_DROP;

	// Check the packet for payload
	if (ip + 1 >= (struct iphdr*) data_end)
        return XDP_PASS;

	if ((ip->ihl) < 5)
        return XDP_DROP;

	if ((ip->protocol == IPPROTO_UDP) && (ip->saddr == MY_IP)) {
		return XDP_DROP;
	}



	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
