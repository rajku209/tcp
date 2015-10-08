#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "checksum.h"
#include "tcp.h"

// Power of 2
#define MAXSOCKETS 512

int sd;
struct tcp_socket** sockets;
int next_index;

void* socket_read_loop(void* arg) {
    void* buffer = malloc(4096);
    ssize_t amt;
    struct tcp_header* tcphdr;
    uint32_t srcaddr_nw;
    uint32_t destaddr_nw;
    uint32_t iphdr_len;
    uint16_t msg_len;
    while (1) {
        amt = recv(sd, buffer, 4096, 0);
        if (amt == -1) {
            if (errno == EINTR) {
                // It returned due to a signal, just wait longer
                printf("Signal\n");
                continue;
            } else {
                // Either the socket closed, or something bad happened
                printf("TCP Loop is terminating\n");
                break;
            }
        } else if (amt == 4096) {
            printf("Packet size is >= 4 KiB; dropping it\n");
            continue;
        }
        /* IPv4 specific handling - I could make a struct for this. */
        srcaddr_nw = ((uint32_t*) buffer)[3];
        destaddr_nw = ((uint32_t*) buffer)[4];
        iphdr_len = (((uint8_t*) buffer)[0] & 0xF) << 2;
        msg_len = ntohs(((uint16_t*) buffer)[1]);
        tcphdr = buffer + iphdr_len; //skip IP header
        if (get_checksum((struct in_addr*) &srcaddr_nw,
                         (struct in_addr*) &destaddr_nw,
                         tcphdr, msg_len - iphdr_len)) {
            printf("Incorrect TCP checksum, dropping packet\n");
            continue;
        }
        
        printf("TODO: handle the packet that was received\n");
    }
    free(buffer);
    return NULL;
}

int tcp_init() {
    pthread_t readthread;
    sd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sd < 0) {
        printf("Could not initialize socket\n");
        return -1;
    }
    sockets = malloc(MAXSOCKETS * sizeof(struct tcp_socket*));
    memset(sockets, 0, MAXSOCKETS * sizeof(struct tcp_socket*));
    next_index = 0;
    pthread_create(&readthread, NULL, &socket_read_loop, NULL);
    return 0;
}

void init_header(struct tcp_header* tcphdr) {
    // Set reserved bits to 0
    tcphdr->offsetflags.bits.reserved = 0;
}

void _set_checksum(struct tcp_socket* tcpsock, void* data, size_t len) {
    struct tcp_header* tcphdr = data;
    uint16_t cksum;
    tcphdr->checksum = 0;
    cksum = get_checksum(&tcpsock->local_addr.sin_addr,
                         &tcpsock->remote_addr.sin_addr, data, len);
    tcphdr->checksum = cksum;
}

void _send_data(struct tcp_socket* tcpsock, void* data, size_t len) {
    ssize_t sent;
    /* Set the relevant fields of the TCP header. */
    struct tcp_header* tcphdr = data;
    tcphdr->srcport = tcpsock->local_addr.sin_port;
    tcphdr->destport = tcpsock->remote_addr.sin_port;
    tcphdr->offsetflags.bits.dataoffset = sizeof(struct tcp_header) >> 2;
    tcphdr->urgentptr = 0; // I technically don't need this, since URG == 0
    _set_checksum(tcpsock, data, len);
    
    sent = sendto(sd, data, len, 0, (struct sockaddr*) &tcpsock->remote_addr,
                  sizeof(struct sockaddr_in));
    if (sent < 0) {
        perror("Could not send data");
    }
}

void _send_tcp_ack(struct tcp_socket* tcpsock, uint8_t flags, int NS) {
    struct tcp_header tcphdr;
    printf("Sending ACK\n");
    tcphdr.seqnum = htonl(tcpsock->seqnum);
    tcphdr.acknum = htonl(tcpsock->acknum);
    tcphdr.offsetflags.flat = (uint16_t) flags;
    tcphdr.offsetflags.bits.NS = NS;
    _send_data(tcpsock, &tcphdr, sizeof(struct tcp_header));
}

void active_open(struct tcp_socket* tcpsock, struct sockaddr_in* dest) {
    tcpsock->remote_addr = *dest;
    /* Some initialization to reset the connection. */
    tcpsock->acknum = 0;
    tcpsock->seqnum = 0x012faded;
    /* Initiate the TCP handshake */
    _send_tcp_ack(tcpsock, FLAG_SYN, 0);
    tcpsock->state = SYN_SENT;
    tcpsock->seqnum++;
}

/* Creates and binds a TCP socket. */
struct tcp_socket* create_socket(struct sockaddr_in* bindto) {
    // TODO check that the port in bindto is valid and not already occupied
    int init_index = next_index;
    while (!sockets[next_index]) {
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
    sockets[next_index] = tcpsock;
    return tcpsock;
}

void close_socket(struct tcp_socket* tcpsock) {
    sockets[tcpsock->index] = NULL;
    free(tcpsock);
}

void tcp_halt() {
    close(sd);
    free(sockets);
}
