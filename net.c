#include <sys/socket.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

/*
    methods defined here do not seem to work very well with socks
*/

/*
    read up to buffl bytes from socket. 
    if FIN arrives then set buffl to number of bytes read n <= buffl
    and return
*/
int
net_read_all(int sfd, __u_char * buff, size_t * buffl)
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

int 
net_write_all(int sfd, void * buff, size_t buffl) 
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

    return 0;
}