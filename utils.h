#ifndef UTILS_H_
#define UTILS_H_

#include <stdint.h>
#include <time.h>

/* TIME UTILITIES */
void delay_to_abs(struct timespec* dest, const struct timespec* delay);
void abs_to_delay(struct timespec* dest, const struct timespec* abs);
int cmp_timespec(const struct timespec* first, const struct timespec* second);


/* CIRCULAR BUFFER
   The circular buffer can be treated either as a buffer of bytes, or a buffer
   of TCP segments. Don't mix and match the functions unless you know what
   you're doing! */
int cbuf_init(uint8_t* buf, size_t len);

int cbuf_write(uint8_t* buf, uint8_t* data, size_t data_len);
size_t cbuf_read(uint8_t* buf, uint8_t* data, size_t numbytes, int pop);
size_t cbuf_pop(uint8_t* data, size_t numbytes);
size_t cbuf_free_space(uint8_t* buf);

int cbuf_write_segment(uint8_t* buf, uint8_t* segment, size_t seglen);
size_t cbuf_pop_segment(uint8_t* buf, size_t segsize);
size_t cbuf_peek_segment_size(uint8_t* buf);
size_t cbuf_peek_segment(uint8_t* buf, uint8_t* data, size_t numbytes);

#endif
