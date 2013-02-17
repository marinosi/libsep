#ifndef _SANDBOX_H_
#define _SANDBOX_H_

/* At the moment we support a two-process only privilege separation model */
struct sandbox_cb {
	int fd_host_end;
	int fd_sandbox_end;
	int sandbox_pid;
};

/*
 * Simple RPC facility (sandboxrpc) definitions.
 */
#define	SANDBOX_RPC_REQUEST_HDR_MAGIC	0x29ee2d7eb9143d98
struct sandboxrpc_request_hdr {
	u_int64_t	sandboxrpc_reqhdr_magic;
	u_int32_t	sandboxrpc_reqhdr_seqno;
	u_int32_t	sandboxrpc_reqhdr_opno;
	u_int64_t	sandboxrpc_reqhdr_datalen;
	u_int64_t	sandboxrpc_reqhdr_maxrepdatalen;
	u_int64_t	_sandboxrpc_reqhdr_spare3;
	u_int64_t	_sandboxrpc_reqhdr_spare2;
	u_int64_t	_sandboxrpc_reqhdr_spare1;
	u_int64_t	_sandboxrpc_reqhdr_spare0;
} __packed;

#define	SANDBOX_RPC_REPLY_HDR_MAGIC	0x37cc2e29f5cce29b
struct sandboxrpc_reply_hdr {
	u_int64_t	sandboxrpc_rephdr_magic;
	u_int32_t	sandboxrpc_rephdr_seqno;
	u_int32_t	sandboxrpc_rephdr_opno;
	u_int64_t	sandboxrpc_rephdr_datalen;
	u_int64_t	_sandboxrpc_rephdr_spare4;
	u_int64_t	_sandboxrpc_rephdr_spare3;
	u_int64_t	_sandboxrpc_rephdr_spare2;
	u_int64_t	_sandboxrpc_rephdr_spare1;
	u_int64_t	_sandboxrpc_rephdr_spare0;
} __packed;

#include <sys/uio.h>
/* Prototypes */
void sandbox_create(struct sandbox_cb *scb, void (*sandbox_mainfn)(void));

ssize_t host_recv(struct sandbox_cb *scb, void *buf, size_t len, int flags);
ssize_t host_recv_rights(struct sandbox_cb *scb, void *buf, size_t len, int
	flags, int *fdp, int *fdcountp);
int host_rpc(struct sandbox_cb *scb, u_int32_t opno, struct iovec *req, int
	reqcount, struct iovec *rep, int repcount, size_t *replenp);
int host_rpc_rights(struct sandbox_cb *scb, u_int32_t opno, struct iovec *req,
	int reqcount, int *req_fdp, int req_fdcount, struct iovec *rep, int
	repcount, size_t *replenp, int *rep_fdp, int *rep_fdcountp);
ssize_t host_send(struct sandbox_cb *scb, const void *msg, size_t len, int
	flags);
ssize_t host_send_rights(struct sandbox_cb *scb, const void *msg, size_t len,
	int flags, int *fdp, int fdcount);
ssize_t sandbox_recv(struct sandbox_cb *scb, void *buf, size_t len, int flags);
ssize_t sandbox_recv_rights(struct sandbox_cb *scb, void *buf, size_t len, int
	flags, int *fdp, int *fdcountp);
int sandbox_recvrpc(struct sandbox_cb *scb, u_int32_t *opnop, u_int32_t *seqnop,
	u_char **bufferp, size_t *lenp);
int sandbox_recvrpc_rights(struct sandbox_cb *scb, u_int32_t *opnop, u_int32_t
	*seqnop, u_char **bufferp, size_t *lenp, int *fdp, int *fdcountp);
ssize_t sandbox_send(struct sandbox_cb *scb, const void *msg, size_t len, int
	flags);
ssize_t sandbox_send_rights(struct sandbox_cb *scb, const void *msg, size_t len,
	int flags, int *fdp, int fdcount);
int sandbox_sendrpc(struct sandbox_cb *scb, u_int32_t opno, u_int32_t seqno,
	struct iovec *rep, int repcount);
int sandbox_sendrpc_rights(struct sandbox_cb *scb, u_int32_t opno, u_int32_t
	seqno, struct iovec *rep, int repcount, int *fdp, int fdcount);
#endif /* _SANDBOX_H_ */
