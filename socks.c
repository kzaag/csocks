#include <sys/socket.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "socks.h"

struct socks_negotiate_req {
    __u_char __ver;
    __u_char __nmethods;
    __u_char * __methods; 
};

typedef struct socks_negotiate_req socks_nreq_t;
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

SOCKADDR_IN 
socks_default_sockaddr_in()
{
    struct sockaddr_in res;

    res.sin_family = AF_INET;
    res.sin_port = htons(9050);
    res.sin_addr.s_addr = 0x0100007F;

    return res;
}

int 
read_all(int sfd, void * buff, size_t * buffl) 
{
    ssize_t nor = 0, totr = 0;

    while(1) {
        if((nor = read(sfd, buff+totr, *buffl-totr)) < 0) {
            return -1;
        }

        if(nor == 0) {
            *buffl = totr;
            return 0;
        }

        if((size_t)nor == (*buffl-totr)) {
            break;
        }

        totr += nor;
    } 

    return 0; 
}

int 
write_all(int sfd, void * buff, size_t buffl) 
{
    ssize_t nowr = 0, totwr, wrrem;

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

    return 0;
}

int 
socks_negotiate(int sfd, __u_char ver, __u_char nmethods, __u_char * methods)
{
    socks_nreq_t req;
    socks_nres_t res;
    size_t ressz = SOCKS_NRES_SZ;

    req.__ver = ver;
    req.__nmethods = nmethods;
    req.__methods = methods;

    if(write_all(sfd, &req, SOCKS_NREQ_SZ) != 0) {
        return -1;
    }

    if(read_all(sfd, &res, &ressz)) {
        return -1;
    }

    if(ressz != SOCKS_NRES_SZ) {
        printf("invalid size read\n");
        return -1;
    }

    if(res.__ver != req.__ver) {
        printf("invalid res [ ver ]: %u\n", res.__ver);
        return -1;
    }

    if(res.__method == SOCKS_M_UNACCEPT) {
        printf("remote rejected method\n");
        return -1;
    }

    return 0;
}

int 
socks_close(int sfd) 
{
    if(sfd > 0) {
        close(sfd);
    }
}

socks_res_t *
__get_socks_response(void * resbuf, size_t resbufl)
{

}

void
__free_socks_response(socks_res_t * res)
{
    if(res->__addr != NULL) {
        free(res->__addr);
    }
}

int 
socks_request_in(int sfd, __u_char ver, __u_char cmd, SOCKADDR_IN addr)
{
    struct socks_in req;
    socks_res_t * res;
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

    if((res = __get_socks_response(res, ressz)) == NULL) {
        return -1;
    }
    
    // either return response or process it?
    __free_socks_response(res);

    return 0;
}

int
socks_request_in6(int sfd, __u_char ver, __u_char cmd, SOCKADDR_IN6 addr)
{
    struct socks_in6 req;
    socks_res_t * res;
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

    if((res = __get_socks_response(res, ressz)) == NULL) {
        return -1;
    }
    
    // either return response or process it?
    __free_socks_response(res);

    return 0;
}

/*
    domain_str must be null terminated string
*/
int
socks_request_domain_s(int sfd, __u_char ver, __u_char cmd, char * domain_str)
{
    /* implement */
}

