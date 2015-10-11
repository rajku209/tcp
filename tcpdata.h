#ifndef TCPDATA_H_
#define TCPDATA_H_

#include <stdint.h>
#include <netinet/in.h>

#include "tcp.h"

int init_tcp_rw(void);
void* socket_read_loop(void*);
int transmit_segment(struct tcp_socket* tcpsock,
                     struct tcp_header* tcpseg, size_t seglen);
void send_tcp_msg(struct tcp_socket* tcpsock, uint8_t flags,
                  uint32_t seqnum, uint32_t acknum,
                  void* data, size_t len, int retransmit);
void send_tcp_ctl_msg(struct tcp_socket* tcpsock, uint8_t flags,
                      uint32_t seqnum, uint32_t acknum, int retransmit);
void halt_tcp_rw(void);

#endif
