#ifndef TCP_H_
#define TCP_H_

#include <pthread.h>
#include <stdint.h>
#include <sys/time.h>
#include <netinet/in.h>

// Power of 2
#define MAXSOCKETS 16

#define FLAG_CWR 0x80
#define FLAG_ECE 0x40
#define FLAG_URG 0x20
#define FLAG_ACK 0x10
#define FLAG_PSH 0x08
#define FLAG_RST 0x04
#define FLAG_SYN 0x02
#define FLAG_FIN 0x01

#define LOCALHOST 0x0100007f

#define MAX_TRIES 5

#define SENDBUFLEN 256
#define RETRBUFLEN 256

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

    /* retries active */
    int retriesactive;
    
    /* time of next retry */
    struct timespec nextretry;

    /* number of retries */
    uint32_t numretries;

    /* send and retransmission buffers */
    uint8_t sendbuf[SENDBUFLEN];
    uint8_t retrbuf[RETRBUFLEN];

    /* locks for retransimission buffer */
    pthread_mutex_t retrbuf_lock;

    /* Sequence Variables for Send, named to mirror RFC spec. */
    struct {
        uint32_t UNA; // Send unacknowledged
        uint32_t NXT; // Send next
        uint16_t WND; // Send window
        uint16_t UP;  // Send urgent pointer
        uint32_t WL1; // Segment sequence number used for last window update
        uint32_t WL2; // Segment ACK number used for last window update
    } SND;
    uint32_t ISS; // Initial send sequence number
    
    /* Sequence Variables for Receive, named to mirror RFC spec. */
    struct {
        uint32_t NXT; // Receive next;
        uint16_t WND; // Receive window
        uint16_t UP; // Receive urgent pointer
    } RCV;
    uint32_t IRS; // Initial receive sequence number
};

int tcp_init(void);
void init_header(struct tcp_header*);
struct tcp_socket* create_socket(struct sockaddr_in*);
void active_open(struct tcp_socket* socket, struct sockaddr_in* dest);
void close_socket(struct tcp_socket*);
void destroy_socket(struct tcp_socket*);

#endif
