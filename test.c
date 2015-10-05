#include <stdio.h>
#include "tcp.h"

int main(int argc, char** argv) {
    struct tcp_header tcph;
    init_header(&tcph);
    printf("Reserved bits: 0x%04x\n", tcph.offsetflags.flat);
    return 0;
}
