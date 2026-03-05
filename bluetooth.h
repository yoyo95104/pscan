#ifndef BLUETOOTH_H
#define BLUETOOTH_H

#include <stdint.h>

#define PASSIVE 1
#define RAW 0
#define HCI_MON_NEW_INDEX 0
#define HCI_MON_DEL_INDEX 1
#define HCI_MON_COMMAND 2
#define HCI_MON_EVENT 3
#define HCI_MON_ACL_TX 4
#define HCI_MON_ACL_RX 5
#define HCI_MON_SCO_TX 6
#define HCI_MON_SCO_RX 7

void scan_bluetooth(int mode);

struct hci_mon_hdr {
  uint16_t opcode;
  uint16_t index;
} __attribute__((packed));

#endif
