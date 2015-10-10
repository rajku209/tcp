#include <stdlib.h>
#include <stdint.h>
#include <netinet/in.h>

#include "tcp.h"

uint16_t get_checksum(struct in_addr* src, struct in_addr* dest,
                      struct tcp_header* tcpseg, size_t len) {
    struct {
        struct in_addr srcaddr;
        struct in_addr destaddr;
        uint8_t reserved;
        uint8_t protocol;
        uint16_t tcplen;
    } __attribute__((packed)) pseudoheader;
    pseudoheader.srcaddr = *src;
    pseudoheader.destaddr = *dest;
    pseudoheader.reserved = 0;
    pseudoheader.protocol = 6; // TCP
    pseudoheader.tcplen = (uint16_t) htons(len);

    /* I'm assuming here that we don't overflow more than 1 << 16 times. */
    uint32_t total = 0;
    uint16_t* current;
    for (current = (uint16_t*) &pseudoheader;
         current < (uint16_t*) (&pseudoheader + 1); current++) {
        total += (uint32_t) *current;
    }
    for (current = (uint16_t*) tcpseg;
         current < (uint16_t*) (((uint8_t*) tcpseg) + len); current++) {
        total += (uint32_t) *current;
    }
    
    while (total >> 16) {
        total = (total & 0xFFFF) + (total >> 16);
    }
    
    return ~((uint16_t) total);
}
