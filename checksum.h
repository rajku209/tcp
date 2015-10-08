#ifndef CHECKSUM_H_
#define CHECKSUM_h_

uint16_t get_checksum(struct in_addr* src, struct in_addr* dest,
                      void* buffer, size_t len);

#endif
