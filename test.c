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

#define MY_IP "127.0.0.1"

struct tcp_socket* sock = NULL;
int sock_deallocated = 0;

void shutdown_socket(int unused __attribute__((__unused__))) {
    sock_deallocated = 1;
    if (sock) {
        printf("Closing connection gracefully...\n");
        close_connection(sock);
        sleep(3);
        destroy_socket(sock);
        exit(0);
    }
}

void* receive_loop(void* arg __attribute__((__unused__))) {
    char buffer[1024];
    size_t read;
    // Assignment in predicate is intentional
    while ((read = read_blocking(sock, (uint8_t*) buffer, 1023))) {
        buffer[read] = '\0';
        printf("%s", buffer);
    }
    return NULL;
}

int main(int argc __attribute__((__unused__)),
         char** argv __attribute__((__unused__))) {
    signal(SIGINT, &shutdown_socket);

    struct sockaddr_in my_addr;
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(37624);
    inet_aton(MY_IP, &my_addr.sin_addr);
    memset(my_addr.sin_zero, 0, 8);

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(1883);
    inet_aton("127.0.0.1", &dest_addr.sin_addr);
    memset(my_addr.sin_zero, 0, 8);

    pthread_t readthread;
    
    tcp_init();
    sock = create_socket(&my_addr);
    pthread_create(&readthread, NULL, &receive_loop, NULL);
    passive_open(sock);
    
    int buf_size = 1024 * sizeof(char);
    char* buf = malloc(buf_size);
    char* result;
    size_t sent;
    // assignment in predicate is intentional
    while ((result = fgets(buf, buf_size, stdin))) {
        if (sock_deallocated) {
            break;
        }
        sent = send_data(sock, (uint8_t*) buf, strlen(buf));
        if (!sent) {
            printf("Warning: no data was sent\n");
        }
    }
    free(buf);

    if (!sock_deallocated) {
        signal(SIGINT, SIG_IGN);
        shutdown_socket(0);
    }
    return 0;
}
