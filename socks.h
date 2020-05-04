#if !defined(SOCKS_H)
#define SOCKS_H

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

/* csocks error codes */

#define SOCKS_ELEN 987001 /* Invalid buffer length */
#define SOCKS_EVER 987002 /* Invalid version of protocol */
#define SOCKS_EREJ 987003 /* Remote rejected method */
#define SOCKS_EADR 987004 /* Invalid address type */

/* ------------------ */


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

#define SOCKS_REP_SUCCESS            0
/*general SOCKS server failure*/
#define SOCKS_REP_FAILURE            1
/*connection not allowed by ruleset*/
#define SOCKS_REP_CONN_NOT_ALLOWED   2
#define SOCKS_REP_NET_UNREACHABLE    3
#define SOCKS_REP_HOST_UNREACHABLE   4
#define SOCKS_REP_CONN_REFUSED       5
#define SOCKS_REP_TTL_EXPIRED        6
/*Command not supported*/
#define SOCKS_REP_CMD_NOT_SUPPORTED  7
/*Address type not supported*/
#define SOCKS_REP_ADDR_NOT_SUPPORTED 8

/*------BEGIN CONVENIENCE METHODS-----*/
/*
    not necessary in protocol itself
    user of this api can specify / use customized socket operations instead of these
*/

typedef struct sockaddr_in socks_addr_in;
typedef struct sockaddr_in6 socks_addr_in6;
typedef struct socks_res socks_res_t;

/*
    default ipv4 local socks addres ( 127.0.0.1:9050 )
*/
socks_addr_in socks_default_sockaddr_in();

socks_addr_in socks_addr(char * ip, in_port_t port);

int socks_sockaddr_in6(char * ip, in_port_t port, socks_addr_in6 * outbuf);

/* ipv4 socks socket */
#define socks_socket_in() \
    socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)

/*
    close socket
*/
void socks_close(int sfd);

#define socks_connect(sfd, saddr) \
    connect(sfd, (const struct sockaddr *)&(saddr), sizeof(saddr))

/*
    socks negotiate without any authentication
*/
#define socks5_negotiate_0(sfd) socks5_negotiate((sfd), 1, &(__u_char){SOCKS_M_0})

#define socks5_connect_in(sfd, addr) \
    socks5_request_in(sfd, SOCKS_CMD_CONN, addr)

#define socks5_connect_in6(sfd, addr6ptr) \
    socks5_request_in6(sfd, SOCKS_CMD_CONN, addr6ptr)

#define socks5_connect_domain(sfd, domainstr, port) \
    socks5_request_domain(sfd, SOCKS_CMD_CONN, domainstr, port)

/*------END CONVENIENCE METHODS-----*/

__u_char socks_res_get_reply(struct socks_res * res);

__u_char socks_res_get_addr_type(struct socks_res * res);

int socks_res_get_addr_in(struct socks_res * res, socks_addr_in * outbuf);

/*
    is not thread safe.
    since its basically wrapper around strerror
*/
char * socks_strerror(int err);

/*
    is not thread safe.
    internally uses same buffer as socks_strerror
*/
char * socks_strrep(__u_char code);

int socks5_negotiate(int sfd, __u_char nmethods, __u_char * methods);

void socks_response_free(socks_res_t * res);

/*
    all request methods NULL on error
    if buffer != NULL user must call socks_response_free to free the returned buffer
*/

socks_res_t * socks5_request(int sfd, __u_char cmd, void * addr, size_t addrl, in_port_t port);

socks_res_t * socks5_request_domain(int sfd, __u_char cmd, char * domainstr, in_port_t port);

#define socks5_request_in(sfd, cmd, addr) \
    socks5_request(sfd, cmd, &addr.sin_addr.s_addr, 4, addr.sin_port)
    
#define socks5_request_in6(sfd, cmd, addr6ptr) \
    socks5_request(sfd, cmd, addr6ptr->sin6_addr.__in6_u.__u6_addr8, 16, addr6ptr->sin6_port)

#endif