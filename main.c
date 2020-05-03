#include "socks.h"
#include <errno.h>
#include <string.h>
#include <stdio.h>

int
main()
{

    int sfd;
    SOCKADDR_IN remote;

    if((sfd = socks_socket_in()) <= 0) {
        goto fail;
    }

    remote = socks_default_sockaddr_in();

    if(socks_connect(sfd, remote) != 0) {
        goto fail;
    }

    if(socks_negotiate_0(sfd, SOCKS_V_5) != 0) {
        goto fail;
    }

    goto ok;

ok:
    socks_close(sfd);
    printf("OK\n");

    return 0;

fail:
    socks_close(sfd);
    printf("Err: %s\n", socks_strerror(errno));
    return 1;

}