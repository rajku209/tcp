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

#define LOCALHOST 0x0100007f

#define RETRY_SECS 2
#define MAX_TRIES 5

struct tcp_header {
    uint16_t srcport;
    uint16_t destport;
    uint32_t seqnum;
    uint32_t acknum;
    uint8_t offset_reserved_NS;
    uint8_t flags;
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

    /* retries active */
    int retriesactive;
    
    /* time of next retry */
    struct timeval nextretry;

    /* number of retries */
    uint32_t numretries;
};

int tcp_init(void);
void init_header(struct tcp_header*);
struct tcp_socket* create_socket(struct sockaddr_in*);
void active_open(struct tcp_socket* socket, struct sockaddr_in* dest);
void close_socket(struct tcp_socket*);

#endif
