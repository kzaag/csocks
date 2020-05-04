#include <sys/socket.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "socks.h"

struct socks_res {
    __u_char __ver;
    /* CMD or REP */
    __u_char __rep;
    __u_char __rsv;
    __u_char __atyp;
    __u_char * __addr;
    in_port_t __port;
};

__u_char
socks_res_get_reply(struct socks_res * res)
{
    return res->__rep;
}

__u_char
socks_res_get_addr_type(struct socks_res * res)
{
    return res->__atyp;
}

int
socks_res_get_addr_in(struct socks_res * res, socks_addr_in * outbuf)
{
    if(res->__atyp != SOCKS_ATYP_IP_V4) {
        errno = SOCKS_EADR;
        return -1;
    }

    outbuf->sin_port = res->__port;
    memcpy(&outbuf->sin_addr, res->__addr , 4);
    return 0;
}

/*
    256 because biggest response ( domain ) 
    contains one octed specifing size + domain itself.
    that gives 1 + 255
*/
#define MAX_RES_SIZE (4 + 256 + 2)

static char outbuff[256];

char *
socks_strrep(__u_char code)
{
    char * ret;

    switch(code){
    case SOCKS_REP_SUCCESS:
        sprintf(outbuff, "Succeeded");
        ret = outbuff;
        break;
    case SOCKS_REP_FAILURE:
        sprintf(outbuff, "General SOCKS server failure");
        ret = outbuff;
        break;
    case SOCKS_REP_CONN_NOT_ALLOWED:
        sprintf(outbuff, "Connection not allowed by ruleset");
        ret = outbuff;
        break;
    case SOCKS_REP_NET_UNREACHABLE:
        sprintf(outbuff, "Network unreachable");
        ret = outbuff;
        break;
    case SOCKS_REP_HOST_UNREACHABLE:
        sprintf(outbuff, "Host unreachable");
        ret = outbuff;
        break;
    case SOCKS_REP_CONN_REFUSED:
        sprintf(outbuff, "Connection refused");
        ret = outbuff;
        break;
    case SOCKS_REP_TTL_EXPIRED:
        sprintf(outbuff, "TTL expired");
        ret = outbuff;
        break;
    case SOCKS_REP_CMD_NOT_SUPPORTED:
        sprintf(outbuff, "Command not supported");
        ret = outbuff;
        break;
    case SOCKS_REP_ADDR_NOT_SUPPORTED:
        sprintf(outbuff, "Address type not supported");
        ret = outbuff;
        break;
    default:
        sprintf(outbuff, "Uknown");
        ret = outbuff;
        break;
    }

    return ret;
}

char * 
socks_strerror(int err) 
{
    int wr = 0;
    char * ret;

    switch(err) {
    case SOCKS_ELEN:
        wr += sprintf(outbuff, "Invalid length of the buffer");
        ret = outbuff;
        break;
    case SOCKS_EVER:
        wr += sprintf(outbuff, "Invalid version of protocol");
        ret = outbuff;
        break;
    case SOCKS_EREJ:
        wr += sprintf(outbuff, "Remote rejected method");
        ret = outbuff;
        break;
    case SOCKS_EADR:
        wr += sprintf(outbuff, "Invalid address type");
        ret = outbuff;
        break;
    default:
        ret = strerror(err);
    }

    return ret;
}

socks_addr_in
socks_addr(char * ip, in_port_t port)
{
    struct sockaddr_in res;

    res.sin_family = AF_INET;
    res.sin_port = htons(port);
    res.sin_addr.s_addr = inet_addr(ip);

    return res;
}

int
socks_sockaddr_in6(char * ip, in_port_t port, socks_addr_in6 * outbuf)
{
    if (inet_pton(AF_INET6, ip, &outbuf->sin6_addr) != 1) {
        return -1;
    } 

    outbuf->sin6_port = port;
    outbuf->sin6_family = AF_INET6;

    return 0;
}

socks_addr_in 
socks_default_sockaddr_in()
{
    struct sockaddr_in res;

    res.sin_family = AF_INET;
    res.sin_port = htons(9050);
    res.sin_addr.s_addr = 0x0100007F;

    return res;
}

int 
socks5_negotiate(int sfd, __u_char nmethods, __u_char * methods)
{
    __u_char * req;
    __u_char res[2];
    size_t i;

    if((req = malloc(2 + nmethods)) == NULL) {
        return -1;
    }

    req[0] = SOCKS_V_5;
    req[1] = nmethods;
    for(i = 0; i < nmethods; i++) {
        req[i+2] = methods[i];
    }

    if(write(sfd, req, 2+nmethods) != 2+nmethods) {
        if(errno == 0)
            errno = SOCKS_ELEN;
        goto fin;
    }

    if(read(sfd, res, 2) != 2) {
        errno = SOCKS_ELEN;
        goto fin;
    }

    if(res[0] != req[0]) {
        errno = SOCKS_EVER;
        goto fin;
    }

    if(res[1] == SOCKS_M_UNACCEPT) {
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
__get_socks_response(__u_char * resbuf, size_t resbufl)
{
    if(resbufl < 10) {
        errno = SOCKS_ELEN;
        return NULL;
    }

    __u_char * addr;
    socks_res_t * res;

    if((res = malloc(sizeof(socks_res_t))) == NULL){
        return NULL;
    }

    res->__ver = resbuf[0];
    res->__rep = resbuf[1];
    res->__rsv = resbuf[2];
    res->__atyp = resbuf[3];

    __u_char asize, offset = 0;

    switch(res->__atyp) {
    case SOCKS_ATYP_IP_V4:
        asize = 4;
        break;
    case SOCKS_ATYP_IP_V6:
        asize = 16;
        break;
    case SOCKS_ATYP_DOMAINNAME:
        offset = 1;
        asize = resbuf[4];
        break;
    default:
        errno = SOCKS_EVER;
        free(res);
        return NULL;
    }

    if(resbufl < (size_t)(4+offset+asize+2)) {
        free(res);
        errno = SOCKS_ELEN;
        return NULL;
    }

    if((addr = malloc(asize)) == NULL) {
        free(res);
        return NULL;
    }

    memcpy(addr, resbuf+4+offset, asize);
    res->__addr = addr;
    memcpy(&res->__port, resbuf+4+offset+asize, 2);

    return res;
}

void
socks_response_free(socks_res_t * res)
{
    if(res == NULL) {
        return;
    }

    if(res->__addr != NULL) {
        free(res->__addr);
    }

    free(res);
}

socks_res_t *
socks5_request(int sfd, __u_char cmd, void * addr, size_t addrl, in_port_t port)
{
    __u_char req[6+addrl];
    __u_char res[MAX_RES_SIZE];
    socks_res_t * sres;
    ssize_t rd;

    req[0] = SOCKS_V_5;
    req[1] = cmd;
    req[2] = 0;
    switch(addrl) {
    case 4:
        req[3] = SOCKS_ATYP_IP_V4;
        break;
    case 16:
        req[3] = SOCKS_ATYP_IP_V6;
        break;
    default:
        req[3] = SOCKS_ATYP_DOMAINNAME;
        break;
    }
    memcpy(req+4, addr, addrl);
    memcpy(req+4+addrl, &port, 2);

    if((size_t)write(sfd, req, 6+addrl)!=(6+addrl)) {
        if(errno == 0)
            errno = SOCKS_ELEN;
        return NULL;
    }

    if((rd = read(sfd, res, MAX_RES_SIZE)) < 0) {
        return NULL;
    }
    
    if((sres = __get_socks_response(res, rd)) == NULL) {
        return NULL;
    }

    if(sres->__ver != SOCKS_V_5) {
        errno = SOCKS_EVER;
        return NULL;
    }

    return sres;
}

/*
    domainstr is domain no more than 255 characters null terminated.
    port is host order destination port number
*/
socks_res_t *
socks5_request_domain(int sfd, __u_char cmd, char * domainstr, in_port_t port)
{
    socks_res_t * res;
    __u_char addrl;

    if(strlen(domainstr) > 255) {
        errno = EOVERFLOW;
        return NULL;
    }

    addrl = (__u_char)strlen(domainstr);

    char addr[addrl+1];

    addr[0] = addrl;
    memcpy(addr+1, domainstr, addrl);

    res = socks5_request(sfd, cmd, addr, addrl+1, htons(port));

    return res;
}


