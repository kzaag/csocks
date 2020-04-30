#if !defined(SOCKS_H)
#define SOCKS_H

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define SOCKS_V_4 4
#define SOCKS_V_5 5

#define SOCKS_M_0         0
#define SOCKS_M_GSSAPI    1
#define SOCKS_M_USER_PASS 2
#define SOCKS_M_UNACCEPT  0xFF

#define SOCKS_CMD_CONN          1
#define SOCKS_CMD_BIND          2
#define SOCKS_CMD_UDP_ASSOCIATE 3

#define SOCKS_ATYP_IP_V4        1
#define SOCKS_ATYP_DOMAINNAME   3
#define SOCKS_ATYP_IP_V6        4

/*------BEGIN CONVENIENCE METHODS-----*/
/*
    not necessary in protocol itself
    user of this api can specify / use customized socket operations instead of these
*/

typedef struct sockaddr_in SOCKADDR_IN;
typedef struct sockaddr_in6 SOCKADDR_IN6;

/*
    default ipv4 local socks addres ( 127.0.0.1:9050 )
*/
SOCKADDR_IN socks_default_sockaddr_in();

/* ipv4 socks socket */
#define socks_socket_in() \
    socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)

/*
    close socket
*/
int socks_close(int sfd);

#define socks_connect(sfd, saddr) \
    connect(sfd, (const struct sockaddr *)&(saddr), sizeof(saddr))

/*
    socks negotiate without any authentication
*/
#define socks_negotiate_0(sfd, ver) socks_negotiate((sfd), (ver), 1, &(__u_char){1})

/*------END CONVENIENCE METHODS-----*/

int socks_negotiate(int sfd, __u_char ver, __u_char nmethods, __u_char * methods);




#endif