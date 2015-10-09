#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>

#include "checksum.h"
#include "tcp.h"
#include "tcpdata.h"

struct itimerval time_left;
const struct itimerval ZERO_TIME = {
    .it_interval = {
        .tv_sec = 0,
        .tv_usec = 0
    },
    .it_value = {
        .tv_sec = 0,
        .tv_usec = 0
    }
};

struct tcp_socket* sockets[MAXSOCKETS];
int next_index;

void _socket_receive(struct tcp_socket* tcpsock, struct tcp_header* tcphdr,
                     size_t len) {
    printf("Received packet for socket %d!\n", tcpsock->index);
}

void _dispatch_packet(struct tcp_header* tcphdr, size_t packet_len,
                      uint32_t srcaddr_nw, uint32_t destaddr_nw) {
    int i;
    struct tcp_socket* curr;
    for (i = 0; i < MAXSOCKETS; i++) {
        if (sockets[i]) {
            curr = sockets[i];
            if (addr_to_int(&curr->local_addr.sin_addr) == destaddr_nw &&
                addr_to_int(&curr->remote_addr.sin_addr) == srcaddr_nw &&
                curr->local_addr.sin_port == tcphdr->destport &&
                curr->remote_addr.sin_port == tcphdr->srcport) {
                _socket_receive(curr, tcphdr, packet_len);
                break;
            }
        }
    }
}

void _set_timer() {
    int i;
    struct tcp_socket* curr;
    struct timeval* soonest = NULL;
    setitimer(ITIMER_REAL, &ZERO_TIME, NULL); // cancel existing timer
    for (i = 0; i < MAXSOCKETS; i++) {
        curr = sockets[i];
        if (curr && curr->retriesactive) {
            if (!soonest || curr->nextretry.tv_sec < soonest->tv_sec ||
                (curr->nextretry.tv_sec == soonest->tv_sec &&
                 curr->nextretry.tv_usec < soonest->tv_usec)) {
                soonest = &curr->nextretry;
            }
        }
    }
    if (soonest) {
        time_left.it_value = *soonest;
        setitimer(ITIMER_REAL, &time_left, NULL);
    }
}


void _tcp_timer_handler(int x) {
    int i;
    struct tcp_socket* curr;
    for (i = 0; i < MAXSOCKETS; i++) {
        curr = sockets[i];
        if (curr && curr->retriesactive) {
            if(++curr->numretries >= MAX_TRIES) {
                // GIVE UP
                printf("Exceeded maximum retries: give up\n");
                curr->retriesactive = 0;
                // TODO terminate connection
                continue;
            }
            switch (curr->state) {
            case LISTEN:
                printf("WARNING: Listening socket has retries activated\n");
                curr->retriesactive = 0;
                break;
            case SYN_SENT:
                send_tcp_flag_msg(curr, FLAG_SYN, 0);
                break;
            default:
                printf("Not yet implemented retry in this state\n");
            }
        }
    }
    _set_timer();
}

int tcp_init() {
    pthread_t readthread;
    if (init_tcp_rw()) {
        return -1;
    }
    memset(sockets, 0, MAXSOCKETS * sizeof(struct tcp_socket*));
    next_index = 0;
    pthread_create(&readthread, NULL, &socket_read_loop, _dispatch_packet);
    signal(SIGALRM, _tcp_timer_handler);
    memset(&time_left, 0, sizeof(time_left));
    time_left.it_value.tv_sec = 2;
    return 0;
}

void active_open(struct tcp_socket* tcpsock, struct sockaddr_in* dest) {
    tcpsock->remote_addr = *dest;
    if (addr_to_int(&dest->sin_addr) == LOCALHOST) {
        *((uint32_t*) &tcpsock->local_addr.sin_addr) = LOCALHOST;
    }
    /* Some initialization to reset the connection. */
    tcpsock->acknum = 0;
    tcpsock->seqnum = 0x012faded;
    /* Initiate the TCP handshake */
    send_tcp_flag_msg(tcpsock, FLAG_SYN, 0);
    tcpsock->retriesactive = 1;
    tcpsock->nextretry.tv_sec = RETRY_SECS;
    tcpsock->nextretry.tv_usec = 0;
    tcpsock->numretries = 0;
    tcpsock->state = SYN_SENT;
    tcpsock->seqnum++;
    _set_timer();
}

/* Creates and binds a TCP socket. */
struct tcp_socket* create_socket(struct sockaddr_in* bindto) {
    // TODO check that the port in bindto is valid and not already occupied
    int init_index = next_index;
    while (sockets[next_index]) {
        next_index = (next_index + 1) & (MAXSOCKETS - 1);
        if (init_index == next_index) {
            return NULL;
        }
    }
    struct tcp_socket* tcpsock = malloc(sizeof(struct tcp_socket));
    tcpsock->index = next_index;
    tcpsock->local_addr = *bindto;
    /* For safety. You can remove this memset. */
    memset(&tcpsock->remote_addr, 0, sizeof(struct sockaddr_in));
    tcpsock->state = CLOSED;
    tcpsock->local_window = 1024;
    tcpsock->seqnum = 0;
    tcpsock->retriesactive = 0;
    memset(&tcpsock->nextretry, 0, sizeof(tcpsock->nextretry));
    tcpsock->numretries = 0;
    sockets[next_index] = tcpsock;
    return tcpsock;
}

void close_socket(struct tcp_socket* tcpsock) {
    sockets[tcpsock->index] = NULL;
    free(tcpsock);
}

void tcp_halt() {
    int i;
    for (i = 0; i < MAXSOCKETS; i++) {
        if (sockets[i]) {
            close_socket(sockets[i]);
        }
    }
    halt_tcp_rw();
}
