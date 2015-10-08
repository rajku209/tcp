#ifndef TCP_H_
#define TCP_H_

#include <stdint.h>
#include <netinet/in.h>

#define FLAG_CWR 0b10000000
#define FLAG_ECE 0b01000000
#define FLAG_URG 0b00100000
#define FLAG_ACK 0b00010000
#define FLAG_PSH 0b00001000
#define FLAG_RST 0b00000100
#define FLAG_SYN 0b00000010
#define FLAG_FIN 0b00000001

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
} __attribute__((packed));

enum tcp_state { LISTEN, SYN_SENT, SYN_RECEIVED, ESTABLISHED, FIN_WAIT_1,
                 FIN_WAIT_2, CLOSE_WAIT, CLOSING, LAST_ACK, TIME_WAIT, CLOSED };

/* The Transmission Control Block for a TCP socket. */
struct tcp_socket {
    /* ID of this socket. */
    int index;
    
    /* local and remote addresses */
    struct sockaddr_in local_addr;
    struct sockaddr_in remote_addr;
    
    /* current connection state */
    enum tcp_state state;

    /* local window size */
    uint16_t local_window;

    /* current sequence number */
    uint32_t seqnum;

    /* last acknowledgement */
    uint32_t acknum;
};

int tcp_init(void);
void init_header(struct tcp_header*);
struct tcp_socket* create_socket(struct sockaddr_in*);
void close_socket(struct tcp_socket*);

#endif
