#define _GNU_SOURCE
#define __USE_GNU
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include "global.h"
#include "mod.h"
#include "scan.h"
#include "version.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <getopt.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define OPT_FILTER 1000
#define BLOCK_SIZE (4096 * 16)
#define FRAME_SIZE 2048
#define BLOCK_NR 64

struct priv {};

volatile sig_atomic_t running = 1;

void handle_sigint(int sig) {
  (void)sig;
  running = 0;
}

int main(int argc, char *argv[]) {
  char *filename = NULL;
  int module_loaded = 0;
  char *interface = NULL;
  int count = 0;
  struct option options[] = {{"file", required_argument, 0, 'f'},
                             {"help", no_argument, 0, 'h'},
                             {"filter", required_argument, 0, OPT_FILTER},
                             {"interface", required_argument, 0, 'i'},
                             {"version", no_argument, 0, 'v'},
                             {"count", required_argument, 0, 'c'},
                             {0, 0, 0, 0}};
  int opt;
  while ((opt = getopt_long(argc, argv, "f:hi:c:b:", options, NULL)) != -1) {
    switch (opt) {
    case 'f':
      filename = optarg;
      break;
    case OPT_FILTER:
      struct filter_args args = {NULL, NULL, 0, 0, 0, 0};
      parse_filter_string(optarg, &args);
      char *params = parse_filter(&args);
      printf("params: %s", params);
      if (load_module(params) == 0)
        module_loaded = 1;
      free(args.ip);
      free(args.dip);
      break;
    case 'i':
      interface = optarg;
      break;
    case 'v':
      printf("Version: %s\nBuild Date: %s\n", APP_VERSION, BUILD_DATE);
      break;
    case 'c':
      count = atoi(optarg);
      break;
    default:
      fprintf(
          stderr,
          "Usage: %s [-f filename] [-filter \" targetport ip dip proto startrange endrange\"] [-i "
          "interface name][--version][--count int]\n",
          argv[0]);
      exit(EXIT_FAILURE);
    }
  }
  int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (fd < 0)
    return 1;
  int version = TPACKET_V3;
  if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) ==
      -1)
    perror("T3_PACKET_VERSION");
  struct tpacket_req3 req;
  memset(&req, 0, sizeof(req));
  req.tp_block_size = BLOCK_SIZE;
  req.tp_frame_size = FRAME_SIZE;
  req.tp_block_nr = BLOCK_NR;
  req.tp_frame_nr = (BLOCK_SIZE / FRAME_SIZE) * BLOCK_NR;
  req.tp_retire_blk_tov = 60;
  req.tp_sizeof_priv = TPACKET_ALIGN(sizeof(struct priv));
  req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;
  if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) == -1)
    perror("Packet_RX_RING");
  if (interface) {
    struct sockaddr_ll sll;
    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1)
      perror("ioctl");
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) == -1)
      perror("bind");
  }
  signal(SIGINT, handle_sigint);
  scan(fd, req, filename, count);
  if (module_loaded == 1) {
    unload_module();
  }
  close(fd);
  return 0;
}
