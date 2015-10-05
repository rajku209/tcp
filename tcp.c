#include "tcp.h"

void init_header(struct tcp_header* tcphdr) {
    // Set reserved bits to 0
    tcphdr->offsetflags.bits.reserved = 0;
}
