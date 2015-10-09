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
const struct timeval WAIT_TIME = {
    .tv_sec = 60,
    .tv_usec = 0
};
const struct timeval RETRY_TIME = {
    .tv_sec = 2,
    .tv_usec = 0
};

struct tcp_socket* sockets[MAXSOCKETS];
int next_index;

void _enable_retries(struct tcp_socket* tcpsock) {
    tcpsock->numretries = 0;
    tcpsock->retriesactive = 1;
    tcpsock->nextretry = RETRY_TIME;
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

void _socket_receive(struct tcp_socket* tcpsock, struct tcp_header* tcphdr,
                     size_t len) {
    printf("Received packet for socket %d!\n", tcpsock->index);
    if (tcphdr->flags & FLAG_RST) {
        switch(tcpsock->state) {
        case LISTEN:
        case SYN_SENT:
        case SYN_RECEIVED:
	    printf("Connection could not be initialized\n");
            tcpsock->state = LISTEN;
            break;
        default:
	    printf("Connection lost\n");
            tcpsock->state = CLOSED;
            break;
        }
        tcpsock->retriesactive = 0;
    } else {
        switch (tcpsock->state) {
        case ESTABLISHED:
            printf("Receipt in ESTABLISHED state is not yet implemented\n");
            break;
        case CLOSE_WAIT:
        case TIME_WAIT:
        case CLOSED:
            send_tcp_flag_msg(tcpsock, FLAG_RST, 0);
            break;
        case LISTEN:
            if (tcphdr->flags == FLAG_SYN) {
                tcpsock->state = SYN_RECEIVED;
                tcpsock->acknum = ntohl(tcphdr->seqnum) + 1;
                send_tcp_flag_msg(tcpsock, FLAG_SYN | FLAG_ACK, 0);
            } else {
                send_tcp_flag_msg(tcpsock, FLAG_RST, 0);
            }
            break;
        case SYN_SENT:
            if (tcphdr->flags == FLAG_SYN) {
                send_tcp_flag_msg(tcpsock, FLAG_ACK, 0);
                tcpsock->state = SYN_RECEIVED;
            } else if (tcphdr->flags == (FLAG_SYN | FLAG_ACK)
                       && ntohl(tcphdr->acknum) == tcpsock->seqnum + 1) {
                tcpsock->state = ESTABLISHED;
                tcpsock->seqnum++;
                tcpsock->acknum = ntohl(tcphdr->seqnum) + 1;
                send_tcp_flag_msg(tcpsock, FLAG_ACK, 0);
                tcpsock->retriesactive = 0; // we don't expect a reponse to this
            } else {
                send_tcp_flag_msg(tcpsock, FLAG_RST, 0);
            }
            break;
        case SYN_RECEIVED:
            if (tcphdr->flags == FLAG_ACK) {
                send_tcp_flag_msg(tcpsock, FLAG_ACK, 0);
                tcpsock->state = ESTABLISHED;
            } else {
                send_tcp_flag_msg(tcpsock, FLAG_RST, 0);
            }
            break;
        case FIN_WAIT_1:
            if (tcphdr->flags == FLAG_ACK) {
                tcpsock->state = FIN_WAIT_2;
            } else if (tcphdr->flags == FLAG_FIN) {
                send_tcp_flag_msg(tcpsock, FLAG_ACK, 0);
                _enable_retries(tcpsock);
                tcpsock->state = CLOSING;
            } else {
                send_tcp_flag_msg(tcpsock, FLAG_RST, 0);
            }
            break;
        case FIN_WAIT_2:
            if (tcphdr->flags == FLAG_FIN) {
                send_tcp_flag_msg(tcpsock, FLAG_ACK, 0);
                tcpsock->state = TIME_WAIT;
                _enable_retries(tcpsock);
                tcpsock->nextretry = WAIT_TIME;
            } else {
                send_tcp_flag_msg(tcpsock, FLAG_RST, 0);
            }
            break;
        case CLOSING:
            if (tcphdr->flags == FLAG_ACK) {
                tcpsock->state = TIME_WAIT;
            } else {
                send_tcp_flag_msg(tcpsock, FLAG_RST, 0);
            }
            break;
        case LAST_ACK:
            if (tcphdr->flags == FLAG_ACK) {
                tcpsock->state = CLOSED;
                tcpsock->retriesactive = 0;
            } else {
                send_tcp_flag_msg(tcpsock, FLAG_RST, 0);
            }
            break;
        }
    }
    _set_timer();
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

void _tcp_timer_handler(int unused) {
    int i;
    struct tcp_socket* curr;
    for (i = 0; i < MAXSOCKETS; i++) {
        curr = sockets[i];
        if (curr && curr->retriesactive) {
            if(++curr->numretries >= MAX_TRIES) {
                // GIVE UP
                printf("Exceeded maximum retries: give up\n");
                // TODO Do I need to do anything else here?
                curr->state = TIME_WAIT;
                curr->nextretry = WAIT_TIME;
                continue;
            }
            switch (curr->state) {
            case CLOSED:
            case LISTEN:
            case FIN_WAIT_2:
                printf("WARNING: socket has retries activated in bad state\n");
                curr->retriesactive = 0;
                break;
            case SYN_SENT:
                send_tcp_flag_msg(curr, FLAG_SYN, 0);
                break;
            case SYN_RECEIVED:
                send_tcp_flag_msg(curr, FLAG_SYN | FLAG_ACK, 0);
                break;
            case CLOSE_WAIT:
            case CLOSING:
                send_tcp_flag_msg(curr, FLAG_ACK, 0);
                break;
            case FIN_WAIT_1:
            case LAST_ACK:
                send_tcp_flag_msg(curr, FLAG_FIN, 0);
                break;
            case ESTABLISHED:
                printf("Retry behavior for ESTABLISHED not yet implemented\n");
                break;
            case TIME_WAIT:
                curr->retriesactive = 0;
                curr->state = CLOSED;
                break;
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
    _enable_retries(tcpsock);
    tcpsock->state = SYN_SENT;
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
    /* TODO Currently, I just send the FIN immediately.
       I need to revise this to put FIN on the current segment queue. */
    switch(tcpsock->state) {
    case LISTEN:
    case SYN_SENT:
        tcpsock->state = CLOSED;
        tcpsock->retriesactive = 0;
        break;
    case SYN_RECEIVED:
    case ESTABLISHED:
        tcpsock->state = FIN_WAIT_1;
        send_tcp_flag_msg(tcpsock, FLAG_FIN, 0);
        _enable_retries(tcpsock);
        break;
    case CLOSE_WAIT:
        tcpsock->state = LAST_ACK;
        send_tcp_flag_msg(tcpsock, FLAG_FIN, 0);
        _enable_retries(tcpsock);
        break;
    default:
        printf("Attempted to close socket in invalid state\n");
        break;
    }
    _set_timer();
}

void destroy_socket(struct tcp_socket* tcpsock) {
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
