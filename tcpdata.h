#ifndef TCPDATA_H_
#define TCPDATA_H_

#include <stdint.h>
#include <netinet/in.h>

#include "tcp.h"

uint32_t addr_to_int(struct in_addr*);
int init_tcp_rw(void);
void* socket_read_loop(void*);
void send_tcp_flag_msg(struct tcp_socket* tcpsock, uint8_t flags, int NS);
void halt_tcp_rw(void);

#endif
