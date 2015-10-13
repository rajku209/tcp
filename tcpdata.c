#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "checksum.h"
#include "tcp.h"
#include "utils.h"

/* This file contains the low-level utilities for sending out data via
   a socket and reading data from a socket.
   It is really an extension of tcp.c, but I thought it was more readable
   to split off these functions so tcp.c doesn't get too cluttered. */

int sd;

pthread_mutex_t sendlock;

/* The only link I have to tcp.c; this function is called when I find a valid
   TCP packet. */
void _dispatch_packet(struct tcp_header*, size_t, uint32_t, uint32_t);

int init_tcp_rw() {
    sd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sd < 0) {
        printf("Could not initialize socket\n");
        return 1;
    }
    pthread_mutex_init(&sendlock, NULL);
    return 0;
}

void* socket_read_loop(void* unused __attribute__((__unused__))) {
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
        tcphdr = (struct tcp_header*) (((uint8_t*) buffer) + iphdr_len);
        if (srcaddr_nw != LOCALHOST &&
            get_checksum((struct in_addr*) &srcaddr_nw,
                         (struct in_addr*) &destaddr_nw,
                         tcphdr, msg_len - iphdr_len)) {
            // Incorrect checksum, drop packet
            continue;
        }
        
        // We received a valid packet
        _dispatch_packet(tcphdr, msg_len - iphdr_len, srcaddr_nw, destaddr_nw);
    }
    free(buffer);
    return NULL;
}

/* Should not be used directly except to transmit fully formed segments (which
   may be useful, for example, to send retries. */
int transmit_segment(struct tcp_socket* tcpsock,
                     struct tcp_header* tcpseg, size_t seglen) {
    ssize_t sent = -1;
    errno = 0;
    pthread_mutex_lock(&sendlock);
    sent = sendto(sd, tcpseg, seglen, 0,
                  (struct sockaddr*) &tcpsock->remote_addr,
                  sizeof(tcpsock->remote_addr));
    if (sent < 0) {
        perror("Could not send data");
    }
    pthread_mutex_unlock(&sendlock);
    return sent;
}

/* The NS bit is never set in this implementation. */
void send_tcp_msg(struct tcp_socket* tcpsock, uint8_t flags,
                  uint32_t seqnum, uint32_t acknum,
                  void* msgbody, size_t msgbody_len, int retransmit) {
    uint16_t cksum;
    size_t len = msgbody_len + sizeof(struct tcp_header);
    struct tcp_header* tcpseg = malloc(len);
    if (msgbody_len) {
        memcpy(tcpseg + 1, msgbody, msgbody_len);
    }
    tcpseg->seqnum = htonl(seqnum);
    tcpseg->acknum = htonl(acknum);
    tcpseg->winsize = htons(tcpsock->RCV.WND);
    tcpseg->urgentptr = htons(tcpsock->SND.UP);
    tcpseg->flags = flags;
    tcpseg->offset_reserved_NS = 0; // for now, no offset
    /* Set the relevant fields of the TCP header. */
    tcpseg->srcport = tcpsock->local_addr.sin_port;
    tcpseg->destport = tcpsock->remote_addr.sin_port;
    tcpseg->offset_reserved_NS |= (((uint8_t) sizeof(struct tcp_header)) << 2);
    tcpseg->urgentptr = 0; // I never send out urgent messages
    tcpseg->checksum = 0;
    cksum = get_checksum(&tcpsock->local_addr.sin_addr,
                         &tcpsock->remote_addr.sin_addr, tcpseg, len);
    tcpseg->checksum = cksum;
    transmit_segment(tcpsock, tcpseg, len);
    if (retransmit) {
        // Put this segment on the retransmit queue
        if (cbuf_write_segment(tcpsock->retrbuf, (uint8_t*) tcpseg, len) < 0) {
            printf("Retransmit queue is full for socket %d\n", tcpsock->index);
        }
    }
    free(tcpseg);
}

/* Like send_tcp_msg, but doesn't have a message body. */
void send_tcp_ctl_msg(struct tcp_socket* tcpsock, uint8_t flags,
                      uint32_t seqnum, uint32_t acknum, int retransmit) {
    send_tcp_msg(tcpsock, flags, seqnum, acknum, NULL, 0, retransmit);
}

void halt_tcp_rw() {
    pthread_mutex_destroy(&sendlock);
    close(sd);
}
