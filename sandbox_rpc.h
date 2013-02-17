#ifndef _SANDBOX_RPC_H_
#define _SANDBOX_RPC_H_

#include <sys/types.h>

/* Prototypes */
void _sandbox_dispose_rights(int *fdp, int fdcount);
int _sandbox_rpc_receive_rights(struct msghdr *msg, int *fdp, int *fdcountp);
ssize_t _sandbox_rpc_send(int fd, const void *msg, size_t len, int flags);
ssize_t _sandbox_rpc_send_rights(int fd, const void *msg, size_t len, int
	flags, int *fdp, int fdcount);
ssize_t _sandbox_rpc_recv(int fd, void *buf, size_t len, int flags);
ssize_t _sandbox_rpc_recv_rights(int fd, void *buf, size_t len, int flags, int
	*fdp, int *fdcountp);

#endif /* _SANDBOX_RPC_H_ */
