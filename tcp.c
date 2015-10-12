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
#include "utils.h"

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
const struct timespec WAIT_TIME = {
    .tv_sec = 60,
    .tv_nsec = 0
};
const struct timespec RETRY_TIME = {
    .tv_sec = 2,
    .tv_nsec = 0
};

struct tcp_socket* sockets[MAXSOCKETS];
int next_index;

void _set_timer() {
    int i;
    struct tcp_socket* curr;
    struct timespec* soonest = NULL;
    struct timespec diff;
    setitimer(ITIMER_REAL, &ZERO_TIME, NULL); // cancel existing timer
    for (i = 0; i < MAXSOCKETS; i++) {
        curr = sockets[i];
        if (curr && curr->retriesactive) {
            if (!soonest || curr->nextretry.tv_sec < soonest->tv_sec ||
                (curr->nextretry.tv_sec == soonest->tv_sec &&
                 curr->nextretry.tv_nsec < soonest->tv_nsec)) {
                soonest = &curr->nextretry;
            }
        }
    }
    if (soonest) {
        abs_to_delay(&diff, soonest);
        time_left.it_value.tv_sec = diff.tv_sec;
        time_left.it_value.tv_usec = (diff.tv_nsec / 1000) +
            ((diff.tv_nsec % 1000) > 0);
        if (time_left.it_value.tv_sec < 0 ||
            (time_left.it_value.tv_sec == 0 &&
             time_left.it_value.tv_usec == 0)) {
            time_left.it_value.tv_sec = 0;
            time_left.it_value.tv_usec = 1;
        }
        setitimer(ITIMER_REAL, &time_left, NULL);
    }
}

void _switch_state(struct tcp_socket* tcpsock, enum tcp_state newstate) {
    int retriesactive = tcpsock->retriesactive;
    tcpsock->state = newstate;
    switch (newstate) {
    case CLOSED:
        // delete the TCB
        tcpsock->activeopen = 0;
        cbuf_init(tcpsock->sendbuf, SENDBUFLEN);
        cbuf_init(tcpsock->recvbuf, RECVBUFLEN);
        cbuf_init(tcpsock->retrbuf, RETRBUFLEN);
        // fallthrough is intentional
    case FIN_WAIT_1:
    case FIN_WAIT_2:
        tcpsock->retriesactive = 0;
        break;
    default:
        if (newstate == TIME_WAIT) {
            delay_to_abs(&tcpsock->nextretry, &WAIT_TIME);
        } else {
            delay_to_abs(&tcpsock->nextretry, &RETRY_TIME);
        }
        tcpsock->numretries = 0;
        tcpsock->retriesactive = 1;
        break;
    }
    if (retriesactive != tcpsock->retriesactive) {
        _set_timer();
    }
}

void _process_ack(struct tcp_socket* tcpsock, uint32_t ack) {
    struct tcp_header retrhdr; // the header of the segment on the queue
    size_t segsize; // the size of the segment on the queue

    pthread_mutex_lock(&tcpsock->retrbuf_lock);
    // assignment is intended in the predicate of this while loop
    while ((segsize = cbuf_peek_segment_size(tcpsock->retrbuf))) {
        cbuf_peek_segment(tcpsock->retrbuf,
                          (uint8_t*) &retrhdr, sizeof(retrhdr));
        if (ntohl(retrhdr.acknum) < ack) {
            cbuf_pop_segment(tcpsock->retrbuf, segsize);
        } else {
            break;
        }
    }
    pthread_mutex_unlock(&tcpsock->retrbuf_lock);
}

void _socket_receive(struct tcp_socket* tcpsock, struct tcp_header* tcphdr,
                     size_t len) {
    int got_ack;
    uint32_t ack;
    uint8_t* data_start;
    uint8_t header_len;
    uint16_t seg_len, max_len;
    uint32_t seg_seq;
    uint32_t temp;
    int accept_seg;
    printf("Segment arrives for socket %d!\n", tcpsock->index);
    switch (tcpsock->state) {
    case CLOSED:
        if (tcphdr->flags & FLAG_RST) {
            break;
        } else if (tcphdr->flags & FLAG_ACK) {
            send_tcp_ctl_msg(tcpsock, FLAG_RST | FLAG_ACK,
                             0, ntohl(tcphdr->seqnum) + len, 0);
        } else {
            send_tcp_ctl_msg(tcpsock, FLAG_RST, ntohl(tcphdr->acknum), 0, 0);
        }
        break;
    case LISTEN:
        if (tcphdr->flags & FLAG_RST) {
            break;
        } else if (tcphdr->flags & FLAG_ACK) {
            send_tcp_ctl_msg(tcpsock, FLAG_RST, ntohl(tcphdr->acknum), 0, 0);
        } else if (tcphdr->flags & FLAG_SYN) {
            // TODO check for security/compartment, and precedence
            tcpsock->IRS = ntohl(tcphdr->seqnum);
            tcpsock->RCV.NXT = tcpsock->IRS + 1;
            _switch_state(tcpsock, SYN_RECEIVED);
            send_tcp_ctl_msg(tcpsock, FLAG_SYN | FLAG_ACK,
                             tcpsock->ISS, tcpsock->RCV.NXT, 1);
        }
        break;
    case SYN_SENT:
        got_ack = 0;
        if (tcphdr->flags & FLAG_ACK) {
            ack = ntohl(tcphdr->acknum);
            if (ack <= tcpsock->ISS || ack > tcpsock->SND.NXT) {
                if (tcphdr->flags & FLAG_RST) {
                    break;
                }
                send_tcp_ctl_msg(tcpsock, FLAG_RST, ack, 0, 0);
                break;
            }
            got_ack = (ack >= tcpsock->SND.UNA && ack <= tcpsock->SND.NXT);
            // got_ack is 1 if the ack is acceptable, 0 otherwise
        }
        if (tcphdr->flags & FLAG_RST) {
            if (got_ack) {
                printf("Connection reset on socket %d\n", tcpsock->index);
                _switch_state(tcpsock, CLOSED);
            }
            break;
        }

        // TODO check security/compartment and precedence

        if (tcphdr->flags & FLAG_SYN) {
            tcpsock->IRS = ntohl(tcphdr->seqnum);
            tcpsock->RCV.NXT = tcpsock->IRS + 1;
            if (got_ack) {
                tcpsock->SND.UNA = ack;
                _process_ack(tcpsock, ack);
            }
            if (tcpsock->SND.UNA > tcpsock->ISS) { // if we got SYN-ACK...
                _switch_state(tcpsock, ESTABLISHED);
                send_tcp_ctl_msg(tcpsock, FLAG_ACK,
                                 tcpsock->SND.NXT, tcpsock->RCV.NXT, 0);
                // Include other controls queued for transmission
            } else { // handle simultaneous connection initiation
                _switch_state(tcpsock, SYN_RECEIVED);
                send_tcp_ctl_msg(tcpsock, FLAG_SYN | FLAG_ACK,
                                 tcpsock->ISS, tcpsock->RCV.NXT, 1);
            }
        }
        break;
    default:
        header_len = (tcphdr->offset_reserved_NS >> 2) & (uint8_t) 0xFC;
        seg_len = len - header_len;
        seg_seq = ntohl(tcphdr->seqnum);
        accept_seg = 0;

        // I can probably simplify this logic
        if (tcpsock->RCV.WND) {
            accept_seg = (tcpsock->RCV.NXT <= seg_seq &&
                          seg_seq < (tcpsock->RCV.NXT + tcpsock->RCV.WND));
            if (seg_len) {
                temp = seg_seq + seg_len - 1;
                accept_seg = accept_seg || (tcpsock->RCV.NXT <= temp &&
                                            temp < (tcpsock->RCV.NXT +
                                                    tcpsock->RCV.WND));
            }
        } else if (seg_seq == tcpsock->RCV.NXT) {
            // No segments are accepted, but valid ACKs, URGs, RSTs are
            accept_seg = 1;
        }

        // I don't support Selective ACKs. So I just ignore these segments
        if (seg_seq > tcpsock->RCV.NXT) {
            accept_seg = 0;
        }
        if (!accept_seg) {
            if (!(tcphdr->flags & FLAG_RST)) {
                send_tcp_ctl_msg(tcpsock, FLAG_ACK,
                                 tcpsock->SND.NXT, tcpsock->RCV.NXT, 0);
            }
            break;
        }

        if (tcphdr->flags & FLAG_RST) {
            switch (tcpsock->state) {
            case SYN_RECEIVED:
                if (tcpsock->activeopen) {
                    // clear retransmission queue
                    cbuf_init(tcpsock->retrbuf, RETRBUFLEN);
                    _switch_state(tcpsock, LISTEN);
                } else {
                    printf("Connection refused on socket %d\n", tcpsock->index);
                    _switch_state(tcpsock, CLOSED);
                }
                break;
            case ESTABLISHED:
            case FIN_WAIT_1:
            case FIN_WAIT_2:
            case CLOSE_WAIT:
                printf("Connection reset on socket %d\n", tcpsock->index);
                // fallthrough is intentional
            default: // CLOSING, LAST_ACK, TIME_WAIT
                _switch_state(tcpsock, CLOSED);
                break;
            }
            break; // done processing, no matter what state the socket was in
        }

        // TODO check security and precedence

        if (tcphdr->flags & FLAG_SYN) {
            // Panic and terminate connection
            printf("Connection terminated on socket %d: unexpected SYN\n",
                   tcpsock->index);
            send_tcp_ctl_msg(tcpsock, FLAG_RST,
                             tcpsock->SND.NXT, tcpsock->RCV.NXT, 0);
            _switch_state(tcpsock, CLOSED);
            break;
        }

        if (tcphdr->flags & FLAG_ACK) {
            ack = ntohl(tcphdr->acknum);
            switch(tcpsock->state) {
            case SYN_RECEIVED:
                if (ack >= tcpsock->SND.UNA && ack <= tcpsock->SND.NXT) {
                    _switch_state(tcpsock, ESTABLISHED);
                } else {
                    send_tcp_ctl_msg(tcpsock, FLAG_RST,
                                     tcpsock->SND.NXT, tcpsock->RCV.NXT, 0);
                    // stop processing here?
                }
                break;
            case CLOSE_WAIT:
            case FIN_WAIT_1:
            case FIN_WAIT_2:
            case CLOSING:
            case ESTABLISHED:
                if (ack > tcpsock->SND.UNA && ack <= tcpsock->SND.NXT) {
                    tcpsock->SND.UNA = ack;
                    _process_ack(tcpsock, ack);
                    // Update the window if more recent than last update
                    if (seg_seq > tcpsock->SND.WL1 ||
                        (seg_seq == tcpsock->SND.WL1 &&
                         ack >= tcpsock->SND.WL2)) {
                        tcpsock->SND.WND = ntohs(tcphdr->winsize);
                        tcpsock->SND.WL1 = seg_seq;
                        tcpsock->SND.WL2 = ack;
                    }
                } else if (ack > tcpsock->SND.NXT) {
                    printf("Sending suspect ACK\n");
                    send_tcp_ctl_msg(tcpsock, FLAG_ACK, tcpsock->SND.NXT,
                                     ntohl(tcphdr->seqnum), 0);
                    // stop processing and return
                    /* What I really want to do is break the outer switch, but
                       it seems that C doesn't support that directly. */
                    goto dropsegment;
                }
                if (tcpsock->state == FIN_WAIT_1 &&
                    tcpsock->SND.UNA > tcpsock->finseqnum) {
                    if (tcphdr->flags & FLAG_FIN) {
                        _switch_state(tcpsock, TIME_WAIT);
                    } else {
                        _switch_state(tcpsock, FIN_WAIT_2);
                    }
                } else if (tcpsock->state == CLOSING &&
                    tcpsock->SND.UNA > tcpsock->finseqnum) {
                    _switch_state(tcpsock, TIME_WAIT);
                }
                break;
            case LAST_ACK:
                if (ack > tcpsock->finseqnum) {
                    _switch_state(tcpsock, TIME_WAIT);
                }
                break;
            case TIME_WAIT:
                if (tcphdr->flags & FLAG_FIN) {
                    send_tcp_ctl_msg(tcpsock, FLAG_ACK,
                                     tcpsock->SND.NXT, seg_seq, 0);
                }
                _switch_state(tcpsock, TIME_WAIT); // restart the timer
                break;
            default: // CLOSED, LISTEN, or SYN_SENT
                printf("Should never get here: socket %d\n", tcpsock->index);
                break;
            }
        } else {
            break; // drop segment and return
        }

        // TODO check URG

        // Process the actual data received
        switch (tcpsock->state) {
        case ESTABLISHED:
        case FIN_WAIT_1:
        case FIN_WAIT_2:
            // Trim segment to correct length
            data_start = ((uint8_t*) tcphdr) + header_len +
                tcpsock->RCV.NXT - seg_seq;
            max_len = (uint16_t) (tcpsock->RCV.NXT +
                                  tcpsock->RCV.WND - seg_seq);
            if (seg_len > max_len) {
                seg_len = max_len;
            }
            // TODO copy data into buffer and update RCV.WND accordingly
            printf("Got data: %.*s\n", seg_len, (char*) data_start);
            tcpsock->RCV.NXT += seg_len;
            // TODO combine this ack with another outgoing segment if possible
            send_tcp_ctl_msg(tcpsock, FLAG_ACK,
                             tcpsock->SND.NXT, tcpsock->RCV.NXT, 0);
            break;
        default:
            break;
        }

        if (tcphdr->flags & FLAG_FIN) {
            printf("Connection closing\n");
            tcpsock->RCV.NXT = seg_seq + 1;
            send_tcp_ctl_msg(tcpsock, FLAG_ACK,
                             tcpsock->SND.NXT, tcpsock->RCV.NXT, 0);
            switch (tcpsock->state) {
            case SYN_RECEIVED:
            case ESTABLISHED:
                _switch_state(tcpsock, CLOSE_WAIT);
                break;
            case FIN_WAIT_1:
                // FIN-ACK case was already handled above
                _switch_state(tcpsock, CLOSING);
                break;
            case FIN_WAIT_2:
            case TIME_WAIT: // restart timer in this case
                _switch_state(tcpsock, TIME_WAIT);
                break;
            case CLOSE_WAIT:
            case CLOSING:
            case LAST_ACK:
                break;
            default: // CLOSED, LISTEN, or SYN_SENT
                printf("Should never get here: socket %d\n", tcpsock->index);
                break;
            }
        }
        
        break;
    }
    dropsegment:
    _set_timer();
}

void _dispatch_packet(struct tcp_header* tcphdr, size_t packet_len,
                      uint32_t srcaddr_nw, uint32_t destaddr_nw) {
    int i;
    struct tcp_socket* curr;
    for (i = 0; i < MAXSOCKETS; i++) {
        if (sockets[i]) {
            curr = sockets[i];
            if (curr->local_addr.sin_addr.s_addr == destaddr_nw &&
                curr->remote_addr.sin_addr.s_addr == srcaddr_nw &&
                curr->local_addr.sin_port == tcphdr->destport &&
                curr->remote_addr.sin_port == tcphdr->srcport) {
                _socket_receive(curr, tcphdr, packet_len);
                break;
            }
        }
    }
}

void _tcp_perform_retries() {
    int i;
    struct tcp_socket* tcpsock;
    struct timespec now;
    uint8_t retrans_segsize;
    struct tcp_header* segbuf;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
    for (i = 0; i < MAXSOCKETS; i++) {
        tcpsock = sockets[i];
        if (tcpsock && tcpsock->retriesactive &&
            cmp_timespec(&tcpsock->nextretry, &now) <= 0) {
            if (tcpsock->state == TIME_WAIT) {
                _switch_state(tcpsock, CLOSED);
            } else {
                // Check if there's a segment in the retransmission queue
                pthread_mutex_lock(&tcpsock->retrbuf_lock);
                retrans_segsize = cbuf_peek_segment_size(tcpsock->retrbuf);
                if (retrans_segsize) {
                    printf("Retransmitting packet for socket %d\n",
                           tcpsock->index);
                    segbuf = malloc(retrans_segsize);
                    if (cbuf_peek_segment(tcpsock->retrbuf, (uint8_t*) segbuf,
                                          retrans_segsize)) {
                        transmit_segment(tcpsock, segbuf, retrans_segsize);
                    } else {
                        printf("Retransmission buffer is corrupt!\n");
                    }
                    free(segbuf);
                    tcpsock->numretries++;
                }
                pthread_mutex_unlock(&tcpsock->retrbuf_lock);

                if(tcpsock->numretries >= MAX_TRIES) {
                    // GIVE UP
                    printf("Exceeded maximum retries: give up\n");
                    // TODO Do I need to do anything else here?
                    _switch_state(tcpsock, TIME_WAIT);
                    continue;
                }
                
                if (tcpsock->retriesactive) {
                    delay_to_abs(&tcpsock->nextretry, &RETRY_TIME);
                }
            }
        }
    }
    _set_timer();
}

void* tcp_timer_loop(void* arg __attribute__((__unused__))) {
    sigset_t waitfor;
    int signal;
    sigemptyset(&waitfor);
    sigaddset(&waitfor, SIGALRM);
    while (1) {
        if ((errno = sigwait(&waitfor, &signal)) || signal != SIGALRM) {
            if (errno) {
                perror("Could not wait for SIGALRM");
            } else {
                printf("Unsolicited signal %s\n", strsignal(signal));
            }
            pthread_exit(NULL);
        }
        _tcp_perform_retries();
    }
    return NULL;
}

int tcp_init() {
    pthread_t readthread;
    pthread_t retrythread;
    sigset_t toblock;
    if (init_tcp_rw()) {
        return -1;
    }

    /* We block SIGALRM in all threads so the signal is not handled by an
       asynchronous handler. Instead I set up my own POSIX thread to handle
       the signal.

       I'm avoiding an asynchronous handler because it allows me to use
       synchronization primitives like locks that I wouldn't be able to use
       in an asynchronous signal handler. */
    sigemptyset(&toblock);
    sigaddset(&toblock, SIGALRM);
    pthread_sigmask(SIG_BLOCK, &toblock, NULL);
    
    memset(sockets, 0, MAXSOCKETS * sizeof(struct tcp_socket*));
    next_index = 0;
    pthread_create(&readthread, NULL, &socket_read_loop, NULL);
    pthread_create(&retrythread, NULL, &tcp_timer_loop, NULL);
    memset(&time_left, 0, sizeof(time_left));
    time_left.it_value.tv_sec = 2;
    return 0;
}

void active_open(struct tcp_socket* tcpsock, struct sockaddr_in* dest) {
    tcpsock->remote_addr = *dest;
    if (dest->sin_addr.s_addr == LOCALHOST) {
        *((uint32_t*) &tcpsock->local_addr.sin_addr) = LOCALHOST;
    }

    tcpsock->activeopen = 1;
    
    /* Initiate the TCP handshake */
    send_tcp_ctl_msg(tcpsock, FLAG_SYN, tcpsock->ISS, 0, 1);
    _switch_state(tcpsock, SYN_SENT);
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
    tcpsock->activeopen = 0;
    tcpsock->local_addr = *bindto;
    /* For safety. You can remove this memset. */
    memset(&tcpsock->remote_addr, 0, sizeof(struct sockaddr_in));
    tcpsock->state = CLOSED;
    tcpsock->retriesactive = 0;
    memset(&tcpsock->nextretry, 0, sizeof(tcpsock->nextretry));
    tcpsock->numretries = 0;
    cbuf_init(tcpsock->sendbuf, SENDBUFLEN);
    cbuf_init(tcpsock->recvbuf, RECVBUFLEN);
    cbuf_init(tcpsock->retrbuf, RETRBUFLEN);
    if (pthread_mutex_init(&tcpsock->retrbuf_lock, NULL)) {
        printf("Could not initialize retransmission buffer lock\n");
    }

    /* Some initialization to reset the connection. */
    tcpsock->ISS = 0x012faded; // TODO randomly generate this
    tcpsock->SND.UNA = tcpsock->ISS;
    tcpsock->SND.NXT = tcpsock->ISS + 1;
    tcpsock->RCV.WND = cbuf_free_space(tcpsock->recvbuf);
    
    /* I don't need to initialize these fields, but I set them anyway. */
    tcpsock->SND.WND = 0xFFFF;
    tcpsock->SND.WL1 = 0xFFFFFFFF;
    tcpsock->SND.WL2 = 0xFFFFFFFF;
    tcpsock->RCV.NXT = 0xFFFFFFFF;
    tcpsock->RCV.UP = 0xFFFF;
    tcpsock->IRS = 0xFFFFFFFF;
    
    
    sockets[next_index] = tcpsock;
    return tcpsock;
}

void close_socket(struct tcp_socket* tcpsock) {
    /* TODO Currently, I just send the FIN immediately.
       I need to wait for send buffer to empty first. */
    switch(tcpsock->state) {
    case CLOSED:
        printf("Attempted to close non-existent connection: socket %d\n",
               tcpsock->index);
        break;
    case LISTEN:
    case SYN_SENT:
        _switch_state(tcpsock, CLOSED);
        break;
    case SYN_RECEIVED:
    case ESTABLISHED:
        _switch_state(tcpsock, FIN_WAIT_1);
        // Maybe I should set finseqnum in send_tcp_ctl_msg?
        tcpsock->finseqnum = tcpsock->SND.NXT;
        send_tcp_ctl_msg(tcpsock, FLAG_FIN | FLAG_ACK,
                         tcpsock->SND.NXT, tcpsock->RCV.NXT, 1);
        tcpsock->SND.NXT++;
        break;
    case CLOSE_WAIT:
        _switch_state(tcpsock, LAST_ACK);
        tcpsock->finseqnum = tcpsock->SND.NXT;
        send_tcp_ctl_msg(tcpsock, FLAG_FIN | FLAG_ACK,
                         tcpsock->SND.NXT, tcpsock->RCV.NXT, 1);
        tcpsock->SND.NXT++;
        break;
    default:
        printf("Attempted to close socket %d in invalid state\n",
               tcpsock->index);
        break;
    }
    _set_timer();
}

void destroy_socket(struct tcp_socket* tcpsock) {
    sockets[tcpsock->index] = NULL;
    pthread_mutex_destroy(&tcpsock->retrbuf_lock);
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
