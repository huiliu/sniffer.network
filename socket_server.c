/*
 * A simple echo socket server
 *
 * reference:
 * 
 * http://www.ibm.com/developerworks/cn/education/linux/l-sock/section4.html
 * http://www.cnblogs.com/cnspace/archive/2011/07/19/2110891.html
 *
 * client test:
 *              nc localhost 1234
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <event.h>

#define PORT    1234
#define BUFF_SIZE   1024

inline void
Die(char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

void
HandleClient(int sock)
{
    char buff[BUFF_SIZE];
    uint8_t recived = -1;

    if ((recived = recv(sock, buff, BUFF_SIZE, 0)) < 0)
        Die("Failed to recive initial bytes from client");

    while (recived > 0) {
        if (send(sock, buff, recived, 0) != recived)
            Die("Failed to send bytes to client");

        if ((recived = recv(sock, buff, BUFF_SIZE, 0)) < 0)
            Die("Failed to recive additional bytes from client");
    }
    close(sock);
}

int
main(int argc, char **argv)
{
    struct sockaddr_in  addr,
                        client;
    int sock,
        client_sock,
        yes = 1;

    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
    bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr));
    listen(sock, 1);
    
    while (1) {
        unsigned int    clientlen = sizeof(client);
        if ((client_sock =
                accept(sock, (struct sockaddr *)&addr, &clientlen)) < 0)
            Die("Failed to accept client connection");
        fprintf(stdout, "Client connected: %s\n",
                                        inet_ntoa(client.sin_addr));
        HandleClient(client_sock);
    }
    return 0;
}
