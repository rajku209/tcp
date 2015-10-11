#include <stdint.h>
#include <string.h>
#include <time.h>

/* TIME UTILITIES */

/* Sets the time in DEST to be the current time plus DELAY. */
void delay_to_abs(struct timespec* dest, const struct timespec* delay) {
    clock_gettime(CLOCK_MONOTONIC_COARSE, dest);
    dest->tv_sec += delay->tv_sec;
    dest->tv_nsec += delay->tv_nsec;
    if (dest->tv_nsec >= 1000000000) {
        dest->tv_sec += 1;
        dest->tv_nsec -= 1000000000;
    }
}

/* Sets the time in DEST to be the time in ABS minus the current time. */
void abs_to_delay(struct timespec* dest, const struct timespec* abs) {
    clock_gettime(CLOCK_MONOTONIC_COARSE, dest);
    dest->tv_sec = abs->tv_sec - dest->tv_sec;
    dest->tv_nsec = abs->tv_nsec - dest->tv_nsec;
    if (dest->tv_nsec < 0) {
        dest->tv_sec -= 1;
        dest->tv_nsec += 1000000000;
    }
}

int cmp_timespec(const struct timespec* x, const struct timespec* y) {
    if (x->tv_sec == y->tv_sec) {
        if (x->tv_nsec == y->tv_nsec) {
            return 0;
        } else if (x->tv_nsec > y->tv_nsec) {
            return 1;
        } else {
            return -1;
        }
    } else if (x->tv_sec > y->tv_sec) {
        return 1;
    } else {
        return -1;
    }
}

/* CIRCULAR BUFFER */

struct circbuf_header {
    size_t r_index;
    size_t w_index;
    size_t size;
} __attribute__((packed));

int cbuf_init(uint8_t* buf, size_t len) {
    struct circbuf_header* chdr = (struct circbuf_header*) buf;
    if (len < sizeof(struct circbuf_header)) {
        return -1;
    }
    chdr->r_index = 0;
    chdr->w_index = 0;
    chdr->size = len - sizeof(struct circbuf_header);
    return 0;
}

size_t _cbuf_used_space(struct circbuf_header* chdr) {
    if (chdr->w_index >= chdr->r_index) {
        return chdr->w_index - chdr->r_index;
    } else {
        return chdr->size + chdr->w_index - chdr->r_index;
    }
}

/* There's always one byte of lost space so I can distinguish between a full
   buffer and an empty buffer. */
size_t _cbuf_free_space(struct circbuf_header* chdr) {
    return chdr->size - 1 - _cbuf_used_space(chdr);
}

int cbuf_write(uint8_t* buf, uint8_t* data, size_t data_len) {
    struct circbuf_header* chdr = (struct circbuf_header*) buf;
    if (_cbuf_free_space(chdr) < data_len) {
        return -1;
    }
    uint8_t* buf_data = (uint8_t*) (chdr + 1);
    size_t fw_index = (chdr->w_index + data_len) % chdr->size;
    size_t bytes_to_end;
    if (fw_index >= chdr->w_index) {
        memcpy(buf_data + chdr->w_index, data, data_len);
    } else {
        bytes_to_end = chdr->size - chdr->w_index;
        memcpy(buf_data + chdr->w_index, data, bytes_to_end);
        memcpy(buf_data, data + bytes_to_end, data_len - bytes_to_end);
    }
    chdr->w_index = fw_index;
    return 0;
}

void _cbuf_read_unsafe(struct circbuf_header* chdr, uint8_t* data,
                       size_t numbytes, int pop) {
    uint8_t* buf_data = (uint8_t*) (chdr + 1);
    size_t fr_index = (chdr->r_index + numbytes) % chdr->size;
    size_t bytes_to_end;
    if (fr_index >= chdr->r_index) {
        memcpy(data, buf_data + chdr->r_index, numbytes);
    } else {
        bytes_to_end = chdr->size - chdr->r_index;
        memcpy(data, buf_data + chdr->r_index, bytes_to_end);
        memcpy(data + bytes_to_end, buf_data, numbytes - bytes_to_end);
    }
    if (pop) {
        chdr->r_index = fr_index;
    }
}

size_t cbuf_read(uint8_t* buf, uint8_t* data, size_t numbytes, int pop) {
    struct circbuf_header* chdr = (struct circbuf_header*) buf;
    size_t used_space = _cbuf_used_space(chdr);
    if (used_space < numbytes) {
        numbytes = used_space;
    }
    _cbuf_read_unsafe(chdr, data, numbytes, pop);
    return numbytes;
}

/* Reads NBYTES bytes of the first segment into BUF. If there aren't NBYTES
   to read in the buffer, does nothing and returns 0. Otherwise, returns
   the number of bytes read. */
size_t cbuf_peek_segment(uint8_t* buf, uint8_t* data, size_t numbytes) {
    struct circbuf_header* chdr = (struct circbuf_header*) buf;
    size_t used_space = _cbuf_used_space(chdr);
    if (used_space < numbytes + sizeof(size_t)) {
        return 0;
    }
    size_t old_ridx = chdr->r_index;
    chdr->r_index = (chdr->r_index + sizeof(size_t)) % chdr->size;
    _cbuf_read_unsafe(chdr, data, numbytes, 0);
    chdr->r_index = old_ridx;
    return numbytes;
}

size_t cbuf_pop(uint8_t* buf, size_t numbytes) {
    struct circbuf_header* chdr = (struct circbuf_header*) buf;
    size_t used_space = _cbuf_used_space(chdr);
    if (used_space > numbytes) {
        numbytes = used_space;
    }
    chdr->r_index = (chdr->r_index + numbytes) % chdr->size;
    return numbytes;
}

int cbuf_write_segment(uint8_t* buf, uint8_t* segment, size_t seglen) {
    struct circbuf_header* chdr = (struct circbuf_header*) buf;
    if (_cbuf_free_space(chdr) < seglen + sizeof(seglen)) {
        return -1;
    }
    cbuf_write(buf, (uint8_t*) &seglen, sizeof(seglen));
    cbuf_write(buf, segment, seglen);
    return 0;
}

size_t cbuf_peek_segment_size(uint8_t* buf) {
    size_t segsize;
    if (cbuf_read(buf, (uint8_t*) &segsize,
                  sizeof(size_t), 0) < sizeof(size_t)) {
        return 0;
    }
    return segsize;
}

size_t cbuf_pop_segment(uint8_t* buf, size_t segsize) {
    if (!segsize) {
        segsize = cbuf_peek_segment_size(buf);
    }
    return cbuf_pop(buf, segsize + sizeof(size_t));
}
