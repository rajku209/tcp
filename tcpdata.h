#ifndef TCPDATA_H_
#define TCPDATA_H_

#include <stdint.h>
#include <netinet/in.h>

#include "tcp.h"

int init_tcp_rw(void);
void* socket_read_loop(void*);
void send_tcp_msg(struct tcp_socket* tcpsock, uint8_t flags,
                  uint32_t seqnum, uint32_t acknum, void* data, size_t len);
void send_tcp_ctl_msg(struct tcp_socket* tcpsock, uint8_t flags,
                      uint32_t seqnum, uint32_t acknum);
void halt_tcp_rw(void);

#endif
