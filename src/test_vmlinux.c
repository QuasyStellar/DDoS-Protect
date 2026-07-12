#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
SEC("xdp")
int test_bpf(struct xdp_md *ctx) {
    __u32 hash = 0;
    bpf_xdp_metadata_rx_hash(ctx, &hash, NULL);
    return 0;
}
