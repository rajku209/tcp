#include <stdio.h>
#include <sys/select.h>

#include "tcp.h"

int main(int argc, char** argv) {
    tcp_init();
    select(0, NULL, NULL, NULL, NULL);
    return 0;
}
