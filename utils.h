#ifndef UTILS_H_
#define UTILS_H_

#include <stdint.h>
#include <time.h>

/* TIME UTILITIES */
void delay_to_abs(struct timespec* dest, const struct timespec* delay);
void abs_to_delay(struct timespec* dest, const struct timespec* abs);
int cmp_timespec(const struct timespec* first, const struct timespec* second);

/* CIRCULAR BUFFER */
int cbuf_init(uint8_t* buf, size_t len);
int cbuf_write(uint8_t* buf, uint8_t* data, size_t data_len);
size_t cbuf_read(uint8_t* buf, uint8_t* data, size_t numbytes);

#endif
