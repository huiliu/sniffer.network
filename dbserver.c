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
#include <fcntl.h>
#include <assert.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <event.h>

#define PORT    1234
#define CLIENT_NUM  5
#define BUFF_SIZE   1024

struct sockaddr_in  sock_server;

inline void
Die(char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

static int 
setnonblock(int fd)
{
    int flags;
    assert((flags = fcntl(fd, F_GETFL) > -1));
    flags |= O_NONBLOCK;
    assert(fcntl(fd, F_SETFL, flags) > -1);

    return 0;
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

void
read_handle(int fd, short ev, void *argv)
{
    char buff[BUFF_SIZE];
    uint8_t recived = -1;

    if ((recived = recv(fd, buff, BUFF_SIZE, 0)) < 0)
        Die("Failed to recive initial bytes from client");

    if (send(fd, buff, recived, 0) != recived)
        Die("Failed to send bytes to client");

}

void
accept_handle(int fd, short ev, void *argv)
{
    struct sockaddr_in  sock_client;
    int fd_client;
    unsigned int clientlen = sizeof(struct sockaddr_in);
    struct event    ev_client;

    if ((fd_client =accept(fd, (struct sockaddr *)&sock_client,&clientlen)) < 0)
        Die("Failed to accept client connection");

    event_set(&ev_client, fd_client, EV_READ | EV_PERSIST, read_handle, NULL);
    if (event_add(&ev_client, NULL) != 0)
        Die("Failed to add client event");

    close(fd);
}

int
main(int argc, char **argv)
{
    struct event        ev_server,
                        ev_client;
    struct sockaddr_in  sock_client;
    int                 fd_server,
                        fd_client,
                        yes = 1;

    memset(&sock_server, 0, sizeof(struct sockaddr_in));
    sock_server.sin_family = AF_INET;
    sock_server.sin_port = htons(PORT);
    sock_server.sin_addr.s_addr = htonl(INADDR_ANY);

    fd_server = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(fd_server, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
    setnonblock(fd_server);
    if (bind(fd_server, (struct sockaddr *)&sock_server,
                                                sizeof(struct sockaddr)) < 0)
        Die("Failed to bind the server socket");
    if (listen(fd_server, CLIENT_NUM) < 0)
        Die("Failed to listen on server socket");

    event_init();
    event_set(&ev_server, fd_server, EV_READ | EV_PERSIST, accept_handle, NULL);
    if (event_add(&ev_server, NULL) != 0)
        Die("Failed to add accept event");

    event_dispatch();
    
    /*
    while (1) {
        unsigned int clientlen = sizeof(sock_client);
        if ((fd_client =
            accept(fd_server, (struct sockaddr *)&sock_client, &clientlen)) < 0)
            Die("Failed to accpet client's connection");
        fprintf(stdout, "Client connected: %s\n",
                                        inet_ntoa(sock_client.sin_addr));
        HandleClient(fd_client);
    }
    */
    return 0;
}
