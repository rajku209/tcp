#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include "tcp.h"

struct tcp_socket* sock = NULL;

void shutdown_socket(int unused __attribute__((__unused__))) {
    if (sock) {
        printf("Closing connection gracefully...\n");
        close_socket(sock);
        sleep(3);
        destroy_socket(sock);
        exit(0);
    }
}

int main(int argc __attribute__((__unused__)),
         char** argv __attribute__((__unused__))) {
    int rv;

    signal(SIGINT, &shutdown_socket);
    
    struct sockaddr_in my_addr;
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(37624);
    inet_aton("192.168.1.107", &my_addr.sin_addr);
    memset(my_addr.sin_zero, 0, 8);

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(1883);
    inet_aton("127.0.0.1", &dest_addr.sin_addr);
    memset(my_addr.sin_zero, 0, 8);
    
    tcp_init();
    sock = create_socket(&my_addr);
    active_open(sock, &dest_addr);

    while (1) {
        rv = select(0, NULL, NULL, NULL, NULL);
        if (rv == -1 || errno == EINTR) {
            continue;
        } else {
            fprintf(stderr, "main select loop returned\n");
            break;
        }
    }
    return 0;
}
