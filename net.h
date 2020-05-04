
#if !defined(NET_H)
#define NET_H

#include <sys/types.h>

int net_read_all(int sfd, __u_char * buff, size_t * buffl);

int net_write_all(int sfd, void * buff, size_t buffl);

#endif
