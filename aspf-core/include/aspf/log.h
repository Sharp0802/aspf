#pragma once

#include "framework.h"

struct arp_block_event {
  __u64 timestamp;
  __u32 ip;
  __u8 org_mac[6];
  __u8 mod_mac[6];
};
