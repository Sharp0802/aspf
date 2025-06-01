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

#include "aspf/aspf-core.h"
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#define GC_STALE_TIME(ifname)                                                  \
  ("/proc/sys/net/ipv4/neigh/" ifname "/gc_stale_time")

#define HELP_MESSAGE                                                           \
  "Usage:\n"                                                                   \
  " aspf [--help] [<ifname>]\n"                                                \
  "\n"                                                                         \
  "Runs anti-spoofing firewall\n"                                              \
  "\n"                                                                         \
  "Options:\n"                                                                 \
  " -h, --help: prints this message\n"

#define MAC_F "%02X:%02X:%02X:%02X:%02X:%02X"
#define MAC_F_ARG(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]

#define print_error(...) fprintf(stderr, "[err] " __VA_ARGS__)

#define __unused __attribute_maybe_unused__

static volatile bool exiting = false;

static void handle_signal(__unused int _) { exiting = true; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt,
                           va_list args) {
  static char *lv[] = {"[wrn] ", "[inf] ", "[dbg] "};

  FILE *out = level == LIBBPF_WARN ? stderr : stdout;
  fputs(lv[level], out);
  return vfprintf(out, fmt, args);
}

static int handle_event(__unused void *ctx, void *data, size_t len) {
  struct arp_block_event *e = data;
  if (len != sizeof *e) {
    return -1;
  }

  char ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &e->ip, ip, sizeof ip);

  uint64_t ts_ms = e->timestamp / 1000000;
  double ts_s = (double)ts_ms / 1000;

  printf("[arp] [%.2lf] %s : " MAC_F " --> " MAC_F "\n", ts_s, ip,
         MAC_F_ARG(e->org_mac), MAC_F_ARG(e->mod_mac));

  return 0;
}

void print_help() { fprintf(stdout, HELP_MESSAGE); }

int main(int argc, char *argv[]) {
  char buffer[BUFSIZ];

  struct bpf_map *config_table = NULL;
  struct bpf_object *obj = NULL;
  struct bpf_program *prog = NULL;
  struct bpf_xdp_attach_opts opts = {};
  int fd, ifindex, err;
  const char *ifname;

  struct ring_buffer *rb = NULL;
  int map_fd;

  FILE *file;
  __u64 gc_stale_time;

  if (argc < 2) {
    fprintf(stderr, "[err] insufficient arguments\n");
    print_help();
    return -1;
  }
  if (strncmp(argv[1], "-h", 2) == 0 || strncmp(argv[1], "--help", 6) == 0) {
    print_help();
    return 0;
  }

  ifname = argv[1];

  libbpf_set_strict_mode(LIBBPF_STRICT_NONE);
  libbpf_set_print(libbpf_print_fn);

  if (!(ifindex = (int)if_nametoindex(ifname))) {
    print_error("if_nametoindex(): %s\n", strerror(errno));
    return -1;
  }

  snprintf(buffer, sizeof buffer, "%s/aspf.bpf.o", dirname(argv[0]));
  if (!(obj = bpf_object__open_file(buffer, NULL))) {
    print_error("bpf_object__open_file(): %s\n", strerror(errno));
    return -1;
  }

  if (bpf_object__load(obj)) {
    print_error("bpf_object__load(): %s\n", strerror(errno));
    return -1;
  }

  if (!(prog = bpf_object__find_program_by_name(obj, "xdp_pass"))) {
    print_error("program 'xdp_pass' not found\n");
    return -1;
  }

  if ((map_fd = bpf_object__find_map_fd_by_name(obj, "arp_events")) < 0) {
    print_error("map 'arp_events' not found\n");
    return -1;
  }

  if (!(rb = ring_buffer__new(map_fd, handle_event, NULL, NULL))) {
    print_error("failed to create ring buffer\n");
    return -1;
  }

  snprintf(buffer, sizeof buffer, GC_STALE_TIME("%s"), ifname);
  file = fopen(buffer, "r");
  if (!file) {
    print_error("%s: %s\n", buffer, strerror(errno));
    file = fopen(GC_STALE_TIME("default"), O_RDONLY);
  }
  if (!file) {
    print_error("%s: %s\n", GC_STALE_TIME("default"), strerror(errno));
    return -1;
  } else if (fscanf(file, "%lld", &gc_stale_time) == EOF) {
    print_error("failed to read gc_stale_time: %s\n", strerror(errno));
    return -1;
  }
  fclose(file);

  gc_stale_time *= 1000000000;

  if ((config_table = bpf_object__find_map_by_name(obj, "config_table")) < 0) {
    print_error("map 'config_table' not found\n");
    return -1;
  }

  if (bpf_map__update_elem(config_table, &(__u32){CONFIG_GC_STALE_TIME},
                           sizeof(__u32), &gc_stale_time, sizeof gc_stale_time,
                           BPF_ANY) < 0) {
    print_error("failed to set gc_stale_time\n");
    return -1;
  }

  fd = bpf_program__fd(prog);
  if ((err = bpf_xdp_attach(ifindex, fd, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL))) {
    print_error("bpf_xdp_attach failed: %d\n", err);
    return -1;
  }

  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);

  puts("[inf] ctrl+c to exit");
  fflush(stdout);

  while (!exiting) {
    if ((err = ring_buffer__poll(rb, 10)) < 0) {
      print_error("while polling: %s\n", strerror(-err));
      break;
    }
  }

  puts("[inf] exiting...");

  opts.sz = sizeof opts;
  opts.old_prog_fd = fd;

  ring_buffer__free(rb);
  bpf_xdp_detach(ifindex, XDP_FLAGS_REPLACE, &opts);
  bpf_object__close(obj);
  return 0;
}
