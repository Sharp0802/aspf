/*
 * This file is part of ASpf.
 * Copyright (C) 2025  Yeong-won Seo
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#define KERNEL

#include "vmlinux.h"

#include "aspf/aspf-core.h"
#include <bpf/bpf_helpers.h>

#define ETH_P_IP 0x0800
#define ETH_P_ARP 0x0806

#define uintptr(a) ((void *)(uintptr_t)(a))
#define next_of(a) ((void *)((a) + 1))

#define E_INSUFFICIENT_BYTES XDP_PASS

typedef __u8 mac_t[6];

struct ip_mac_entry {
  __u64 timestamp;
  mac_t mac;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, __CONFIG_LAST);
  __type(key, __u32);
  __type(value, __u64);
} config_table SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 1024);
  __type(key, __be32);
  __type(value, struct ip_mac_entry);
} ip_mac_table SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(key_size, 0);
  __uint(value_size, 0);
  __uint(max_entries, 1 << 12);
} arp_events SEC(".maps");

static __always_inline int arp_pass(void *begin, void *end) {
  struct arphdr *arp = begin;
  if (next_of(arp) >= end) {
    return E_INSUFFICIENT_BYTES;
  }

  if (bpf_ntohs(arp->ar_hrd) != 1 || arp->ar_hln != 6 ||
      bpf_ntohs(arp->ar_pro) != ETH_P_IP || arp->ar_pln != 4) {
    return XDP_PASS;
  }

  mac_t *src_hrd = next_of(arp);
  __be32 *src_pro = next_of(src_hrd);
  if (next_of(src_pro) >= end) {
    return E_INSUFFICIENT_BYTES;
  }

  __be32 key = *(__be32 *)src_pro;
  __u64 timestamp = bpf_ktime_get_boot_ns();

  __u64 *p_gc_stale_time =
      bpf_map_lookup_elem(&config_table, &(__u32){CONFIG_GC_STALE_TIME});
  __u64 gc_stale_time =
      p_gc_stale_time ? *p_gc_stale_time : DEFAULT_GC_STALE_TIME;

  struct ip_mac_entry *old = bpf_map_lookup_elem(&ip_mac_table, &key);
  if (old && (timestamp - old->timestamp) <= gc_stale_time) {

    // duplicated claim before cache expiration
    if (__builtin_memcmp(old->mac, src_hrd, sizeof *src_hrd) != 0) {

      struct arp_block_event *e;
      e = bpf_ringbuf_reserve(&arp_events, sizeof *e, 0);

      if (!e) {
        return XDP_DROP;
      }

      e->timestamp = timestamp;
      e->ip = key;
      __builtin_memcpy(e->org_mac, old->mac, 6);
      __builtin_memcpy(e->mod_mac, src_hrd, 6);
      bpf_ringbuf_submit(e, 0);

      return XDP_DROP;
    }
  }

  struct ip_mac_entry entry = {};
  entry.timestamp = timestamp;
  __builtin_memcpy(entry.mac, src_hrd, 6);

  // do not check overflow; it's LRU map
  bpf_map_update_elem(&ip_mac_table, &key, &entry, BPF_ANY);
  return XDP_PASS;
}

SEC("xdp") int xdp_pass(struct xdp_md *ctx) {
  void *begin = uintptr(ctx->data), *end = uintptr(ctx->data_end);

  struct ethhdr *eth = begin;
  void *next = next_of(eth);
  if (next >= end) {
    return E_INSUFFICIENT_BYTES;
  }

  if (bpf_ntohs(eth->h_proto) == ETH_P_ARP) {
    return arp_pass(next, end);
  }

  return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
