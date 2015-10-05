#ifndef TCP_H_
#define TCP_H_

#include <stdint.h>

union offsetflags_hw {
    uint16_t flat;
    struct {
        uint32_t dataoffset  : 4;
        uint32_t reserved    : 3;
        uint32_t NS          : 1;
        uint32_t CWR         : 1;
        uint32_t ECE         : 1;
        uint32_t URG         : 1;
        uint32_t ACK         : 1;
        uint32_t PSH         : 1;
        uint32_t RST         : 1;
        uint32_t SYN         : 1;
        uint32_t FIN         : 1;
    } __attribute__((packed)) bits;
} __attribute__((packed));

struct tcp_header {
    uint16_t srcport;
    uint16_t destport;
    uint32_t seqnum;
    uint32_t acknum;
    union offsetflags_hw offsetflags;
    uint16_t winsize;
    uint16_t checksum;
    uint16_t urgentptr;
    uint32_t options[10];
} __attribute__((packed));

enum tcp_state { LISTEN, SYNSENT, SYNRECEIVED, ESTABLISHED, FINWAIT1, FINWAIT2,
                 CLOSEWAIT, CLOSING, LASTACK, TIMEWAIT, CLOSED };

/* I'm almost certainly going to be adding fields to this struct! */
struct tcp_socket {
    enum tcp_state state;
    uint32_t seqnum;
};

void init_header(struct tcp_header*);

#endif
