#include "global.h"
#include "log.h"
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/ether.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

void hex(const unsigned char *data, int len) {
  for (int i = 0; i < len; i++) {
    printf("%02x ", data[i]);
    if ((i + 1) % 16 == 0)
      printf("\n");
  }
  if (len % 16 != 0)
    printf("\n");
}

void scan(int fd, struct tpacket_req3 req, char *file, int count) {
  int counter = 0;
  FILE *fp = NULL;
  char *global_ext = NULL;
  if (file != NULL) {
    fp = fopen(file, "wb");
    if (!fp)
      perror("fopen");
    else
      setvbuf(fp, NULL, _IOFBF, 1 << 20);
    char *ext = strrchr(file, '.');
    if (ext && ext != file) {
      *ext = '\0';
      global_ext = ext + 1;
      if (strcmp(global_ext, "pcap") == 0) {
        struct pcap_global_header gh = {.magic_number = 0xa1b2c3d4,
                                        .version_major = 2,
                                        .version_minor = 4,
                                        .thiszone = 0,
                                        .sigfigs = 0,
                                        .snaplen = 65535,
                                        .network = 1};
        fwrite(&gh, sizeof(gh), 1, fp);
        fflush(fp);
      } else if (strcmp(global_ext, "pcapng") == 0) {
        fflush(fp);
      }
    }
  }
  size_t ring_size = req.tp_block_nr * req.tp_block_size;
  uint8_t *rx_ring =
      mmap(NULL, ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (rx_ring == MAP_FAILED) {
    perror("mmap");
  }
  struct pollfd pfd = {.fd = fd, .events = POLLIN};
  int block_idx = 0;
  while (running) {
    if (count > 0 && counter >= count)
      break;
    struct tpacket_block_desc *block_hdr =
        (struct tpacket_block_desc *)(rx_ring + block_idx * req.tp_block_size);
    while (!(block_hdr->hdr.bh1.block_status & TP_STATUS_USER)) {
      int ret = poll(&pfd, 1, 1000);
      if (ret < 0)
        perror("poll");
    }
    int num_pkts = block_hdr->hdr.bh1.num_pkts;
    if (num_pkts == 0) {
      block_hdr->hdr.bh1.block_status = TP_STATUS_KERNEL;
      block_idx = (block_idx + 1) % req.tp_block_nr;
      continue;
    }
    struct tpacket3_hdr *pkt_hdr =
        (struct tpacket3_hdr *)((uint8_t *)block_hdr +
                                block_hdr->hdr.bh1.offset_to_first_pkt);
    for (int i = 0; i < num_pkts; i++) {
      unsigned char *data = (unsigned char *)pkt_hdr + pkt_hdr->tp_mac;
      struct ethhdr *eth = (struct ethhdr *)data;
      if (ntohs(eth->h_proto) == ETH_P_IP) {
        struct iphdr *ip =
            (struct iphdr *)((uint8_t *)pkt_hdr + pkt_hdr->tp_net);
        char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip->saddr, src, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ip->daddr, dst, INET_ADDRSTRLEN);
        printf("[IP Packet]\n");
        printf("Source IP: %s \nDst IP: %s\n", src, dst);
        printf("Packet Length: %u bytes\n", pkt_hdr->tp_snaplen);
        time_t ts = pkt_hdr->tp_sec;
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S",
                 localtime(&ts));
        printf("Timestamp: %s\n", time_str);
        printf("Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->h_source[0],
               eth->h_source[1], eth->h_source[2], eth->h_source[3],
               eth->h_source[4], eth->h_source[5]);
        printf("Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->h_dest[0],
               eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4],
               eth->h_dest[5]);
        printf("TTL: %d\n", ip->ttl);
        const char *protocol;
        switch (ip->protocol) {
        case 6:
          protocol = "TCP";
          break;
        case 17:
          protocol = "UDP";
          break;
        case 1:
          protocol = "ICMP";
          break;
        case 58:
          protocol = "IPv6 ICMP";
          break;
        default:
          protocol = "Unknown";
          break;
        }
        printf("Protocol: %s\n", protocol);
        if (ip->protocol == IPPROTO_TCP) {
          struct tcphdr *tcph = (struct tcphdr *)((uint8_t *)ip + ip->ihl * 4);
          printf("Source Port: %u\n", ntohs(tcph->source));
          printf("Destination Port: %u\n", ntohs(tcph->dest));
          if (tcph->syn)
            printf("TCP Flag: SYN\n");
          else if (tcph->ack) {
            printf("TCP Flag: ACK");
            printf("ACK SEQ: %d", tcph->ack_seq);
          } else if (tcph->fin)
            printf("TCP Flag: FIN\n");
          else if (tcph->rst)
            printf("TCP Flag: RST \n");
          else if (tcph->psh)
            printf("TCP Flag: PSH\n");
          else if (tcph->urg)
            printf("TCP Flag: URG \n");
          printf("Sequence: %d\n", tcph->seq);
        } else if (ip->protocol == IPPROTO_UDP) {
          struct udphdr *udph = (struct udphdr *)((uint8_t *)ip + ip->ihl * 4);
          printf("Source Port: %d\n", ntohs(udph->source));
          printf("Destination Port: %d\n", udph->dest);
        }
      } else {
        uint16_t eth_proto = ntohs(eth->h_proto);
        switch (eth_proto) {
        case 0x0806: {
          struct arphdr *arp = (struct arphdr *)(data + sizeof(struct ethhdr));
          const char *op = ntohs(arp->ar_op) == 1   ? "REQUEST"
                           : ntohs(arp->ar_op) == 2 ? "REPLY"
                                                    : "UNKNOWN";
          unsigned char *sha = (unsigned char *)(arp + 1);
          unsigned char *spa = sha + 6;
          unsigned char *tha = spa + 4;
          unsigned char *tpa = tha + 6;
          printf("[ARP] %s\n", op);
          printf("  Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", sha[0],
                 sha[1], sha[2], sha[3], sha[4], sha[5]);
          printf("  Sender IP:  %d.%d.%d.%d\n", spa[0], spa[1], spa[2], spa[3]);
          printf("  Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", tha[0],
                 tha[1], tha[2], tha[3], tha[4], tha[5]);
          printf("  Target IP:  %d.%d.%d.%d\n", tpa[0], tpa[1], tpa[2], tpa[3]);
          break;
        }
        case 0x8100: {
          uint16_t tci = ntohs(*(uint16_t *)(data + sizeof(struct ethhdr)));
          uint16_t vlan_id = tci & 0x0FFF;
          uint8_t priority = (tci >> 13) & 0x7;
          printf("[VLAN 802.1Q]\n");
          printf("  VLAN ID: %u  Priority: %u\n", vlan_id, priority);
          uint16_t inner =
              ntohs(*(uint16_t *)(data + sizeof(struct ethhdr) + 2));
          printf("  Inner EtherType: 0x%04x\n", inner);
          break;
        }

        case 0x88A8: {
          uint16_t outer =
              ntohs(*(uint16_t *)(data + sizeof(struct ethhdr))) & 0x0FFF;
          uint16_t inner =
              ntohs(*(uint16_t *)(data + sizeof(struct ethhdr) + 4)) & 0x0FFF;
          printf("[QinQ 802.1ad] Outer VLAN: %u  Inner VLAN: %u\n", outer,
                 inner);
          break;
        }

        case 0x8035:
          printf("[RARP] Reverse ARP  Length: %u bytes\n", pkt_hdr->tp_snaplen);
          break;

        case 0x0842:
          printf("[Wake-on-LAN]  Length: %u bytes\n", pkt_hdr->tp_snaplen);
          break;
        case 0x8847:
        case 0x8848: {
          uint32_t label_stack =
              ntohl(*(uint32_t *)(data + sizeof(struct ethhdr)));
          uint32_t label = (label_stack >> 12) & 0xFFFFF;
          uint8_t tc = (label_stack >> 9) & 0x7;
          uint8_t s = (label_stack >> 8) & 0x1;
          uint8_t ttl = label_stack & 0xFF;
          printf("[MPLS %s]\n", eth_proto == 0x8847 ? "Unicast" : "Multicast");
          printf("  Label: %u  TC: %u  S: %u  TTL: %u\n", label, tc, s, ttl);
          break;
        }

        case 0x88CC:
          printf("[LLDP] Link Layer Discovery  Length: %u bytes\n",
                 pkt_hdr->tp_snaplen);
          break;

        case 0x888E:
          printf("[802.1X] EAP Authentication  Length: %u bytes\n",
                 pkt_hdr->tp_snaplen);
          break;

        case 0x9000:
          printf("[Loopback]  Length: %u bytes\n", pkt_hdr->tp_snaplen);
          break;

        default:
          printf("[Unknown EtherType: 0x%04x]  Length: %u bytes\n", eth_proto,
                 pkt_hdr->tp_snaplen);
          break;
        }

        printf("Payload:\n");
        hex(data, pkt_hdr->tp_snaplen);
      }
      if (count > 0)
        counter += 1;
      if (fp != NULL)
        logger_write_packet(fp, data, pkt_hdr->tp_snaplen, global_ext);
      pkt_hdr =
          (struct tpacket3_hdr *)((uint8_t *)pkt_hdr + pkt_hdr->tp_next_offset);
    }
    block_idx = (block_idx + 1) % req.tp_block_nr;
    block_hdr->hdr.bh1.block_status = TP_STATUS_KERNEL;
  }
  munmap(rx_ring, ring_size);
  if (fp)
    logger_close(fp);
}
