#include "aspf/aspf-core.h"
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>


static volatile bool exiting = false;

static void handle_signal(int sig) {
  exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list args) {
  static char *lv[] = {
      "[wrn] ",
      "[inf] ",
      "[dbg] "
  };

  FILE *out = level == LIBBPF_WARN ? stderr : stdout;
  fputs(lv[level], out);
  return vfprintf(out, fmt, args);
}

int main(int argc, char *argv[]) {
  struct bpf_object *obj = NULL;
  struct bpf_program *prog = NULL;
  struct bpf_xdp_attach_opts opts = {};
  int fd, ifindex, err;
  const char *ifname;

  if (argc < 2) {
    fprintf(stderr, "[err] insufficient arguments\n");
    fprintf(stdout, "[inf] usage: aspf <ifname>\n");
    return -1;
  }
  ifname = argv[1];

  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
  libbpf_set_print(libbpf_print_fn);

  if (!(ifindex = (int)if_nametoindex(ifname))) {
    perror("if_nametoindex()");
    return -1;
  }

  if (!(obj = bpf_object__open_file("aspf.bpf.o", NULL))) {
    perror("bpf_object__open_file()");
    return -1;
  }

  if (bpf_object__load(obj)) {
    perror("bpf_object__load()");
    return -1;
  }

  if (!(prog = bpf_object__find_program_by_name(obj, "xdp_pass"))) {
    fprintf(stderr, "[err] program 'xdp_pass' not found\n");
    return -1;
  }

  fd = bpf_program__fd(prog);
  if ((err = bpf_xdp_attach(ifindex, fd, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL))) {
    fprintf(stderr, "[err] bpf_xdp_attach failed: %d", err);
    return -1;
  }

  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);

  puts("[inf] ctrl+c to exit");
  fflush(stdout);

  while (!exiting) {

  }

  puts("[inf] exiting...");

  opts.sz = sizeof opts;
  opts.old_prog_fd = fd;

  bpf_xdp_detach(ifindex, XDP_FLAGS_REPLACE, &opts);
  bpf_object__close(obj);
  return 0;
}
