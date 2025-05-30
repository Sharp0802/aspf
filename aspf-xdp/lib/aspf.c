#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("xdp") int xdp_pass(struct xdp_md *ctx) {
  bpf_printk("hello from xdp!\n");
  return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
