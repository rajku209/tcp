#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "tcp.h"
#include "checksum.h"

/* This file contains the low-level utilities for sending out data via
   a socket and reading data from a socket.
   It is really an extension of tcp.c, but I thought it was more readable
   to split off these functions so tcp.c doesn't get too cluttered. */

int sd;

inline uint32_t addr_to_int(struct in_addr* addr) {
    return *((uint32_t*) addr);
}

int init_tcp_rw() {
    sd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sd < 0) {
        printf("Could not initialize socket\n");
        return 1;
    }
    return 0;
}

void* socket_read_loop(void* arg) {
    void* buffer = malloc(4096);
    ssize_t amt;
    struct tcp_header* tcphdr;
    uint32_t srcaddr_nw;
    uint32_t destaddr_nw;
    uint32_t iphdr_len;
    uint16_t msg_len;

    void (*onreceive)(struct tcp_header*, size_t, uint32_t, uint32_t) = arg;
    
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
        if (srcaddr_nw != LOCALHOST &&
            get_checksum((struct in_addr*) &srcaddr_nw,
                         (struct in_addr*) &destaddr_nw,
                         tcphdr, msg_len - iphdr_len)) {
            printf("Incorrect TCP checksum, dropping packet\n");
            continue;
        }
        
        // We received a valid packet
        onreceive(tcphdr, msg_len - iphdr_len, srcaddr_nw, destaddr_nw);
    }
    free(buffer);
    return NULL;
}

void _send_data(struct tcp_socket* tcpsock, void* data, size_t len) {
    ssize_t sent;
    uint16_t cksum;
    /* Set the relevant fields of the TCP header. */
    struct tcp_header* tcphdr = data;
    tcphdr->srcport = tcpsock->local_addr.sin_port;
    tcphdr->destport = tcpsock->remote_addr.sin_port;
    tcphdr->offset_reserved_NS |= (((uint8_t) len) << 2);
    tcphdr->urgentptr = 0; // I never send out urgent messages
    tcphdr->checksum = 0;
    cksum = get_checksum(&tcpsock->local_addr.sin_addr,
                         &tcpsock->remote_addr.sin_addr, data, len);
    tcphdr->checksum = cksum;
    sent = sendto(sd, data, len, 0, (struct sockaddr*) &tcpsock->remote_addr,
                  sizeof(struct sockaddr_in));
    if (sent < 0) {
        perror("Could not send data");
    }
}

void send_tcp_flag_msg(struct tcp_socket* tcpsock, uint8_t flags, int NS) {
    struct tcp_header tcphdr;
    printf("Sending flags\n");
    tcphdr.seqnum = htonl(tcpsock->seqnum);
    tcphdr.acknum = htonl(tcpsock->acknum);
    tcphdr.flags = flags;
    tcphdr.offset_reserved_NS = (NS != 0);
    _send_data(tcpsock, &tcphdr, sizeof(struct tcp_header));
}

void halt_tcp_rw() {
    close(sd);
}
