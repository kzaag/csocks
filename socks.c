#include <sys/socket.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "socks.h"

#define SOCKS_NREQ_SZ (sizeof(socks_nreq_t))

struct socks_negotiate_res {
    __u_char __ver;
    __u_char __method;
};

typedef struct socks_negotiate_res socks_nres_t;
#define SOCKS_NRES_SZ (sizeof(socks_nres_t))

struct socks_hdr {
    __u_char __ver;
    /* CMD or REP */
    __u_char __code;
    __u_char __rsv;
    __u_char __atyp;
};

typedef struct socks_hdr socks_hdr_t;

struct socks_in {
    socks_hdr_t __hdr;
    in_addr_t __addr;
    in_port_t __port;
};

struct socks_in6 {
    socks_hdr_t __hdr;
    struct in6_addr __addr;
    in_port_t __port;
};

struct socks_res {
    socks_hdr_t __hdr;
    void * __addr;
    in_port_t __port;
};

/*
    256 because biggest response ( domain ) 
    contains one octed specifing size + domain itself.
    that gives 1 + 255
*/
#define MAX_RES_SIZE (sizeof(socks_hdr_t) + 256 + 2)

typedef struct socks_res socks_res_t;

static char errbuff[256];

char * 
socks_strerror(int err) 
{
    int wr = 0;
    char * ret;

    switch(err) {
    case SOCKS_ELEN:
        wr += sprintf(errbuff, "Invalid length of the buffer");
        ret = errbuff;
        break;
    case SOCKS_EVER:
        wr += sprintf(errbuff, "Invalid version of protocol");
        ret = errbuff;
        break;
    case SOCKS_EREJ:
        wr += sprintf(errbuff, "Remote rejected method");
        ret = errbuff;
        break;
    default:
        ret = strerror(err);
    }

    return ret;
}

SOCKADDR_IN 
socks_default_sockaddr_in()
{
    struct sockaddr_in res;

    res.sin_family = AF_INET;
    res.sin_port = htons(9050);
    res.sin_addr.s_addr = 0x0100007F;

    return res;
}

/*
    read up to buffl bytes from socket. 
    if FIN arrives then set buffl to number of bytes read n <= buffl
    and return
*/
int
read_all(int sfd, void * buff, size_t * buffl)
{
    ssize_t nor = 0, totr = 0;

    while(1) {
        if((nor = read(sfd, buff+totr, *buffl-totr)) < 0) {
            return -1;
        }

        if(nor == 0) {
            if(totr == 0) {
                /* if we didnt read anything. then its probably connection reset */
                errno = ECONNRESET;
                return -1;
            }
            break;
        }

        totr += nor;

        if((size_t)totr == *buffl) {
            break;
        }
    } 

    *buffl = totr;

    return 0; 
}

/*
    read exactly buffl bytes from socket
    if received lesser than buffl then return -1 and ser errno to SOCKS_ELEN
*/
int
read_size(int sfd, void * buff, size_t buffl) 
{
    size_t actual_len = buffl;

    if(read_all(sfd, buff, &actual_len) != 0) {
        return -1;
    }

    if(actual_len != buffl) {
        errno = SOCKS_ELEN;
        return -1;
    }

    return 0;
}

int 
write_all(int sfd, void * buff, size_t buffl) 
{
    ssize_t nowr = 0, totwr = 0, wrrem;

    while(1) {
        wrrem = buffl-totwr;
        if((nowr = write(sfd+totwr, buff, wrrem)) < 0) {
            return -1;
        }

        if(nowr == wrrem) {
            break;
        }

        totwr += nowr;
    }

    if(shutdown(sfd, SHUT_WR) != 0) {
        return -1;
    }

    return 0;
}

int 
socks_negotiate(int sfd, __u_char ver, __u_char nmethods, __u_char * methods)
{
    /* only ver 5 is supported for now */
    if(ver != SOCKS_V_5) {
        errno = SOCKS_EVER;
        return -1;
    }

    char * req;
    socks_nres_t res;
    size_t ressz = SOCKS_NRES_SZ, i;

    if((req = malloc(2 + nmethods)) == NULL) {
        return -1;
    }

    req[0] = ver;
    req[1] = nmethods;
    for(i = 0; i < nmethods; i++) {
        req[i+2] = methods[i];
    }

    if(write_all(sfd, req, 2+nmethods) != 0) {
        goto fin;
    }

    if(read_size(sfd, &res, ressz)) {
        goto fin;
    }

    if(res.__ver != req[0]) {
        errno = SOCKS_EVER;
        goto fin;
    }

    if(res.__method == SOCKS_M_UNACCEPT) {
        errno = SOCKS_EREJ;
        goto fin;
    }

fin:
    if(req != NULL) {
        free(req);
    }
    return errno == 0 ? 0 : -1;
}

void 
socks_close(int sfd) 
{
    if(sfd > 0) {
        close(sfd);
    }
}

socks_res_t *
__get_socks_response(void * resbuf, size_t resbufl)
{
    (void)resbuf;
    (void)resbufl;
    return NULL;
}

void
__free_socks_response(socks_res_t * res)
{
    if(res == NULL) {
        return;
    }

    if(res->__addr != NULL) {
        free(res->__addr);
    }
}

int 
socks_request_in(int sfd, __u_char ver, __u_char cmd, SOCKADDR_IN addr)
{
    struct socks_in req;
    socks_res_t * sres;
    char res[MAX_RES_SIZE];
    size_t ressz = MAX_RES_SIZE;

    req.__hdr.__ver = ver;
    req.__hdr.__rsv = 0;
    req.__hdr.__code = cmd;
    req.__hdr.__atyp = SOCKS_ATYP_IP_V4;
    req.__addr = addr.sin_addr.s_addr;
    req.__port = addr.sin_port;

    if(write_all(sfd, &req, sizeof(struct socks_in)) != 0) {
        return -1;
    }

    if(read_all(sfd, res, &ressz) != 0) {
        return -1;
    }

    if((sres = __get_socks_response(res, ressz)) == NULL) {
        return -1;
    }
    
    // either return response or process it?
    __free_socks_response(sres);

    return 0;
}

int
socks_request_in6(int sfd, __u_char ver, __u_char cmd, SOCKADDR_IN6 addr)
{
    struct socks_in6 req;
    socks_res_t * sres;
    char res[MAX_RES_SIZE];
    size_t ressz = MAX_RES_SIZE;

    req.__hdr.__ver = ver;
    req.__hdr.__rsv = 0;
    req.__hdr.__code = cmd;
    req.__hdr.__atyp = SOCKS_ATYP_IP_V6;
    memcpy(&req.__addr, &addr.sin6_addr, 16);
    req.__port = addr.sin6_port;

    if(write_all(sfd, &req, sizeof(struct socks_in6)) != 0) {
        return -1;
    }

    if(read_all(sfd, res, &ressz) != 0) {
        return -1;
    }

    if((sres = __get_socks_response(res, ressz)) == NULL) {
        return -1;
    }
    
    // either return response or process it?
    __free_socks_response(sres);

    return 0;
}

/*
    domain_str must be null terminated string
*/
int
socks_request_domain_s(int sfd, __u_char ver, __u_char cmd, char * domain_str)
{
    (void)sfd;
    (void)ver;
    (void)cmd;
    (void)domain_str;
    /* implement */
    return 0;
}

