#include "bluetooth.h"
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

void scan_bluetooth(int mode) {
  if (mode == 0) {
    int sock = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
    if (sock < 0) {
      perror("Creating_socket");
      exit(1);
    }

    struct sockaddr_hci addr = {
        .hci_family = AF_BLUETOOTH,
        .hci_dev = 0,
        .hci_channel = HCI_CHANNEL_RAW,
    };
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
      perror("Error_Binding_socket");
      exit(1);
    }
    struct hci_filter flt;
    hci_filter_clear(&flt);
    hci_filter_all_ptypes(&flt);
    hci_filter_all_events(&flt);
    uint8_t buf[HCI_MAX_FRAME_SIZE];
    while (1) {
      int len = read(sock, buf, sizeof(buf));
      if (len < 0) {
        perror("read");
        break;
      }
      printf("[RAW] type=0x%02x len=%d | ", buf[0], len);
      for (int i = 0; i < len && i < 20; i++)
        printf("%02x ", buf[i]);
      printf("\n");
    }
    close(sock);
  } else if (mode == 1) {
    int sock = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
    if (sock < 0) {
      perror("Bluetooth_socket");
      exit(1);
    }
    struct sockaddr_hci addr = {
        .hci_family = AF_BLUETOOTH,
        .hci_dev = HCI_DEV_NONE,
        .hci_channel = HCI_CHANNEL_MONITOR,
    };
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
      perror("bind");
      exit(1);
    }
    uint8_t buf[HCI_MAX_FRAME_SIZE + sizeof(struct hci_mon_hdr)];
    while (1) {
      int len = read(sock, buf, sizeof(buf));
      if (len < 0) {
        perror("read");
        break;
      }

      struct hci_mon_hdr *hdr = (struct hci_mon_hdr *)buf;
      uint8_t *payload = buf + sizeof(struct hci_mon_hdr);
      int payload_len = len - sizeof(struct hci_mon_hdr);

      const char *dir;
      switch (hdr->opcode) {
      case HCI_MON_COMMAND:
        dir = "CMD  →";
        break;
      case HCI_MON_EVENT:
        dir = "EVT  ←";
        break;
      case HCI_MON_ACL_TX:
        dir = "ACL →";
        break;
      case HCI_MON_ACL_RX:
        dir = "ACL ←";
        break;
      default:
        dir = "OTHER ";
        break;
      }

      printf("[MON] hci%d %s len=%d | ", hdr->index, dir, payload_len);
      for (int i = 0; i < payload_len && i < 20; i++)
        printf("%02x ", payload[i]);
      printf("\n");
    }

    close(sock);
  }
}

int main() {
  scan_bluetooth(RAW);
  return 0;
}
