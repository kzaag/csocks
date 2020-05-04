#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "socks.h"
#include "net.h"

int
main()
{

    int sfd;
    socks_addr_in socksaddr;
    socks_res_t * res = NULL;

    if((sfd = socks_socket_in()) <= 0) {
        goto fin;
    }

    socksaddr = socks_default_sockaddr_in();

    if(socks_connect(sfd, socksaddr) != 0) {
        goto fin;
    }

    if(socks5_negotiate_0(sfd) != 0) {
        goto fin;
    }

    /* ipv4 */
    socks_addr_in remote = socks_addr("54.225.66.103", 80);
    if((res = socks5_connect_in(sfd, remote)) == NULL) {
        goto fin;
    }

    /* domain */

    // if((res = socks5_connect_domain(sfd, "api.ipify.org", 80)) == NULL) {
    //     goto fin;
    // }

    if(socks_res_get_reply(res) != SOCKS_REP_SUCCESS) {
        printf("Invalid response was: %s\n", socks_strrep(socks_res_get_reply(res)));
        goto fin;
    }

    {
        char * http = "GET / HTTP/1.1\r\nHost: api.ipify.org\r\n\r\n", httpres[4096];
        ssize_t resl = 4096-1;

        if(net_write_all(sfd, http, strlen(http)) != 0) {
            goto fin;
        }

        if((resl = read(sfd, (unsigned char *)httpres, resl)) < 0) {
            goto fin;
        }

        httpres[resl] = 0;

        printf("%s\n", httpres);
    }

fin:
    socks_response_free(res);
    socks_close(sfd);
    if(errno == 0) {
        return 0;
    } else {
        fprintf(stderr, "Err: %s\n", socks_strerror(errno));
        return 1;
    }

}