#include <stdio.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <strings.h>
#include <stdlib.h>
#include <errno.h>

#include "sandbox_rpc.h"
#include "sandbox.h"

void
sandbox_create(struct sandbox_cb *scb, void  (*sandbox_mainfn)(void))
{

	int pid, fd_sockpair[2];

	/* Establish a socket pair for host-sandbox */
	fd_sockpair[0] = fd_sockpair[1] = -1;
	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, fd_sockpair) < 0) {
		perror("socketpair");
		exit(1);
	}

	/* Update control block */
	scb->fd_host_end = fd_sockpair[0];
	scb->fd_sandbox_end = fd_sockpair[1];

	/* Spawn sandbox */
	pid = fork();
	if (pid < 0) {
		perror("fork");
		exit(1);
	}

	/* Child-Sandbox */
	if(!pid) {
		sandbox_mainfn();
		exit (0); /* Default action exit */
	}

	/* Update sandbox pid in control block */
	scb->sandbox_pid = pid;
}

/* Simple I/O wrappers. */
ssize_t
host_send(struct sandbox_cb *scb, const void *msg, size_t len, int flags)
{
	return (_sandbox_rpc_send(scb->fd_host_end, msg, len, flags));
}

ssize_t
host_send_rights(struct sandbox_cb *scb, const void *msg, size_t len,
    int flags, int *fdp, int fdcount)
{

	return (_sandbox_rpc_send_rights(scb->fd_host_end, msg, len, flags, fdp,
		fdcount));
}

ssize_t
host_recv(struct sandbox_cb *scb, void *buf, size_t len, int flags)
{

	return (_sandbox_rpc_recv(scb->fd_host_end, buf, len, flags));
}

ssize_t
host_recv_rights(struct sandbox_cb *scb, void *buf, size_t len, int flags,
    int *fdp, int *fdcountp)
{

	return (_sandbox_rpc_recv_rights(scb->fd_host_end, buf, len, flags, fdp,
	    fdcountp));
}

/*
 * Host recv rpc internal routine. Arguments are variable size, so space is
 * allocated by the RPC library rather than the caller, who is expected however
 * to free it with free(3) if desired. We do not expect to receive any file
 * descriptor handles from a sandbox process, so there is no provision for this.
 */
static int
host_recvrpc_internal(struct sandbox_cb *scb, u_int32_t *opnop, u_int32_t
	*seqnop, u_char **bufferp, size_t *lenp)
{
	struct sandboxrpc_reply_hdr rep_hdr;
	size_t totlen;
	ssize_t len;
	u_char *buffer;
	int error;

	/*
	 * Receive our header and validate.
	 */
	len = _sandbox_rpc_recv(scb->fd_host_end, &rep_hdr, sizeof(rep_hdr),
		MSG_WAITALL);
	if (len < 0)
		return (-1);
	if (len != sizeof(rep_hdr)) {
		errno = ECHILD;
		return (-1);
	}

	/*if (rep_hdr.sandboxrpc_rephdr_magic != SANDBOX_RPC_REPLY_HDR_MAGIC ||*/
		/*rep_hdr.sandboxrpc_rephdr_seqno != 0 ||*/
		/*rep_hdr.sandboxrpc_rephdr_opno != opno ||*/
		/*rep_hdr.sandboxrpc_rephdr_datalen > req_hdr.sandboxrpc_reqhdr_maxrepdatalen) {*/
	if (rep_hdr.sandboxrpc_rephdr_magic != SANDBOX_RPC_REPLY_HDR_MAGIC) {
		errno = EBADRPC;
		return (-1);
	}

	/*
	 * Allocate the appropriate space to store the incoming message.
	 */
	buffer = malloc(rep_hdr.sandboxrpc_rephdr_datalen);
	if (buffer == NULL) {
		error = errno;
		return (-1);
	}

	/*
	 * Receive the user data.  Notice that we can partially overwrite the
	 * user buffer but still receive an error.
	 */
	totlen = 0;
	while (totlen < rep_hdr.sandboxrpc_rephdr_datalen) {
		len = _sandbox_rpc_recv(scb->fd_host_end, buffer + totlen,
		    rep_hdr.sandboxrpc_rephdr_datalen - totlen, MSG_WAITALL);
		if (len < 0) {
			error = errno;
			free(buffer);
			return (-1);
		}
		if (len == 0) {
			errno = EPIPE;
			free(buffer);
			return (-1);
		}
		totlen += len;
	}
	*bufferp = buffer;
	*lenp = totlen;
	*opnop = rep_hdr.sandboxrpc_rephdr_opno;
	*seqnop = rep_hdr.sandboxrpc_rephdr_seqno;
	return (0);
}

static int
host_sendrpc_internal(struct sandbox_cb *scb, u_int32_t opno, u_int32_t seqno,
    struct iovec *req, int reqcount, int *fdp, int fdcount)
{
	struct sandboxrpc_request_hdr req_hdr;
	ssize_t len;
	int i;

	bzero(&req_hdr, sizeof(req_hdr));
	req_hdr.sandboxrpc_reqhdr_magic = SANDBOX_RPC_REQUEST_HDR_MAGIC;
	req_hdr.sandboxrpc_reqhdr_seqno = seqno;
	req_hdr.sandboxrpc_reqhdr_opno = opno;
	req_hdr.sandboxrpc_reqhdr_datalen = 0;
	for (i = 0; i < reqcount; i++)
		req_hdr.sandboxrpc_reqhdr_datalen += req[i].iov_len;

	/*
	 * Send our header.
	 */
	if (fdp != NULL)
		len = _sandbox_rpc_send_rights(scb->fd_host_end, &req_hdr,
			sizeof(req_hdr), 0, fdp, fdcount);
	else
		len = _sandbox_rpc_send(scb->fd_host_end, &req_hdr, sizeof(req_hdr), 0);
	if (len < 0)
		return (-1);
	if (len != sizeof(req_hdr)) {
		errno = EPIPE;
		return (-1);
	}

	/*
	 * Send user data.
	 */
	for (i = 0; i < reqcount; i++) {
		len = _sandbox_rpc_send(scb->fd_host_end, req[i].iov_base,
		    req[i].iov_len, 0);
		if (len < 0)
			return (-1);
		if ((size_t)len != req[i].iov_len) {
			errno = EPIPE;
			return (-1);
		}
	}
	return (0);
}
/*
 * Simple libcapsicum RPC facility (sandboxrpc): send a request, get back a
 * reply (up to the size bound of the buffers passed in).  The caller is
 * responsible for retransmitting if the sandbox fails.
 *
 * Right now sequence numbers are unimplemented -- that's fine because we
 * don't need retransmission, and are synchronous.  However, it might not be
 * a bad idea to use them anyway.
 */
static int
host_rpc_internal(struct sandbox_cb *scb, u_int32_t opno, struct iovec *req,
    int reqcount, int *req_fdp, int req_fdcount, struct iovec *rep,
    int repcount, size_t *replenp, int *rep_fdp, int *rep_fdcountp)
{
	struct sandboxrpc_request_hdr req_hdr;
	struct sandboxrpc_reply_hdr rep_hdr;
	size_t left, off, space, totlen, want;
	ssize_t len;
	int i;

	bzero(&req_hdr, sizeof(req_hdr));
	req_hdr.sandboxrpc_reqhdr_magic = SANDBOX_RPC_REQUEST_HDR_MAGIC;
	req_hdr.sandboxrpc_reqhdr_seqno = 0;
	req_hdr.sandboxrpc_reqhdr_opno = opno;
	for (i = 0; i < reqcount; i++)
		req_hdr.sandboxrpc_reqhdr_datalen += req[i].iov_len;
	for (i = 0; i < repcount; i++)
		req_hdr.sandboxrpc_reqhdr_maxrepdatalen += rep[i].iov_len;

	/*
	 * Send our header.
	 */
	if (req_fdp != NULL)
		len = _sandbox_rpc_send_rights(scb->fd_host_end, &req_hdr,
			sizeof(req_hdr), 0, req_fdp, req_fdcount);
	else
		len = _sandbox_rpc_send(scb->fd_host_end, &req_hdr, sizeof(req_hdr),
		    0);
	if (len < 0)
		return (-1);
	if (len != sizeof(req_hdr)) {
		errno = ECHILD;
		return (-1);
	}

	/*
	 * Send the user request.
	 */
	for (i = 0; i < reqcount; i++) {
		len = _sandbox_rpc_send(scb->fd_host_end, req[i].iov_base,
		    req[i].iov_len, 0);
		if (len < 0)
			return (-1);
		if ((size_t)len != req[i].iov_len) {
			errno = ECHILD;
			return (-1);
		}
	}

	/*
	 * Receive our header and validate.
	 */
	if (rep_fdp != NULL)
		len = _sandbox_rpc_recv_rights(scb->fd_host_end, &rep_hdr,
			sizeof(rep_hdr), MSG_WAITALL, rep_fdp, rep_fdcountp);
	else
		len = _sandbox_rpc_recv(scb->fd_host_end, &rep_hdr, sizeof(rep_hdr),
		    MSG_WAITALL);
	if (len < 0)
		return (-1);
	if (len != sizeof(rep_hdr)) {
		if (rep_fdp != NULL)
			_sandbox_dispose_rights(rep_fdp, *rep_fdcountp);
		errno = ECHILD;
		return (-1);
	}

	if (rep_hdr.sandboxrpc_rephdr_magic != SANDBOX_RPC_REPLY_HDR_MAGIC ||
	    rep_hdr.sandboxrpc_rephdr_seqno != 0 ||
	    rep_hdr.sandboxrpc_rephdr_opno != opno ||
	    rep_hdr.sandboxrpc_rephdr_datalen > req_hdr.sandboxrpc_reqhdr_maxrepdatalen) {
		if (rep_fdp != NULL)
			_sandbox_dispose_rights(rep_fdp, *rep_fdcountp);
		errno = EBADRPC;
		return (-1);
	}

	/*
	 * Receive the user data.  Notice that we can partially overwrite the
	 * user buffer but still receive an error.
	 */
	totlen = 0;
	for (i = 0; i < repcount; i++) {
		off = 0;
		while (totlen < rep_hdr.sandboxrpc_rephdr_datalen) {
			space = rep[i].iov_len - off;
			left = rep_hdr.sandboxrpc_rephdr_datalen - totlen;
			want = (space > left) ? space : left;
			len = _sandbox_rpc_recv(scb->fd_host_end,
			    (u_char *)((uintptr_t)rep[i].iov_base + off),
			    want, MSG_WAITALL);
			if (len < 0)
				return (-1);
			if ((size_t)len != want) {
				if (rep_fdp != NULL)
					_sandbox_dispose_rights(rep_fdp,
					    *rep_fdcountp);
				errno = ECHILD;
				return (-1);
			}
			off += len;
			totlen += len;
			if (rep[i].iov_len == off)
				break;
		}
		if (totlen == rep_hdr.sandboxrpc_rephdr_datalen)
			break;
	}
	*replenp = totlen;
	return (0);
}

int
host_rpc(struct sandbox_cb *scb, u_int32_t opno, struct iovec *req,
    int reqcount, struct iovec *rep, int repcount, size_t *replenp)
{

	return (host_rpc_internal(scb, opno, req, reqcount, NULL, 0,
	    rep, repcount, replenp, NULL, NULL));
}

int
host_rpc_rights(struct sandbox_cb *scb, u_int32_t opno, struct iovec *req,
    int reqcount, int *req_fdp, int req_fdcount, struct iovec *rep,
    int repcount, size_t *replenp, int *rep_fdp, int *rep_fdcountp)
{

	return (host_rpc_internal(scb, opno, req, reqcount, req_fdp,
	    req_fdcount, rep, repcount, replenp, rep_fdp, rep_fdcountp));
}

int
host_recvrpc(struct sandbox_cb *scb, u_int32_t *opnop, u_int32_t *seqnop,
	u_char **bufferp, size_t *lenp)
{

	return (host_recvrpc_internal(scb, opnop, seqnop, bufferp, lenp));
}

int
host_sendrpc(struct sandbox_cb *scb, u_int32_t opno, u_int32_t seqno,
    struct iovec *req, int reqcount, int *fdp, int fdcount)
{

	return (host_sendrpc_internal(scb, opno, seqno, req, reqcount, fdp,
		fdcount));
}

ssize_t
sandbox_recv(struct sandbox_cb *scb, void *buf, size_t len, int flags)
{

	return (_sandbox_rpc_recv(scb->fd_sandbox_end, buf, len, flags));
}

ssize_t
sandbox_recv_rights(struct sandbox_cb *scb, void *buf, size_t len, int flags,
    int *fdp, int *fdcountp)
{

	return (_sandbox_rpc_recv_rights(scb->fd_sandbox_end, buf, len, flags, fdp,
		fdcountp));
}

ssize_t
sandbox_send(struct sandbox_cb *scb, const void *msg, size_t len, int flags)
{

	return (_sandbox_rpc_send(scb->fd_sandbox_end, msg, len, flags));
}

ssize_t
sandbox_send_rights(struct sandbox_cb *scb, const void *msg, size_t len,
    int flags, int *fdp, int fdcount)
{

	return (_sandbox_rpc_send_rights(scb->fd_sandbox_end, msg, len, flags, fdp,
		fdcount));
}

/*
 * RPC facility sandbox routines.  Since arguments are variable size, space is
 * allocated by the RPC code rather than the caller, who is expected to free it
 * with free(3) if desired.
 */
static int
sandbox_recvrpc_internal(struct sandbox_cb *scb, u_int32_t *opnop,
    u_int32_t *seqnop, u_char **bufferp, size_t *lenp, int *fdp,
    int *fdcountp)
{
	struct sandboxrpc_request_hdr req_hdr;
	size_t totlen;
	ssize_t len;
	u_char *buffer;
	int error;

	if (fdp != NULL)
		len = _sandbox_rpc_recv_rights(scb->fd_sandbox_end, &req_hdr,
			sizeof(req_hdr), MSG_WAITALL, fdp, fdcountp);
	else
		len = _sandbox_rpc_recv(scb->fd_sandbox_end, &req_hdr, sizeof(req_hdr),
		    MSG_WAITALL);
	if (len < 0)
		return (-1);
	if (len == 0) {
		if (fdp != NULL)
			_sandbox_dispose_rights(fdp, *fdcountp);
		errno = EPIPE;
		return (-1);
	}
	if (len != sizeof(req_hdr)) {
		if (fdp != NULL)
			_sandbox_dispose_rights(fdp, *fdcountp);
		errno = EBADMSG;
		return (-1);
	}

	if (req_hdr.sandboxrpc_reqhdr_magic != SANDBOX_RPC_REQUEST_HDR_MAGIC) {
		if (fdp != NULL)
			_sandbox_dispose_rights(fdp, *fdcountp);
		errno = EBADMSG;
		return (-1);
	}

	/*
	 * XXXRW: Should we check that the receive data fits in the address
	 * space of the sandbox?
	 *
	 * XXXRW: If malloc() fails, we should drain the right amount of data
	 * from the socket so that the next RPC will succeed.  Possibly we
	 * should also reply with an error from this layer to the sender?
	 * What about if there are other socket errors, such as EINTR?
	 */
	buffer = malloc(req_hdr.sandboxrpc_reqhdr_datalen);
	if (buffer == NULL) {
		error = errno;
		if (fdp != NULL)
			_sandbox_dispose_rights(fdp, *fdcountp);
		errno = error;
		return (-1);
	}

	/*
	 * XXXRW: Likewise, how to handle failure at this stage?
	 */
	totlen = 0;
	while (totlen < req_hdr.sandboxrpc_reqhdr_datalen) {
		len = _sandbox_rpc_recv(scb->fd_sandbox_end, buffer + totlen,
		    req_hdr.sandboxrpc_reqhdr_datalen - totlen, MSG_WAITALL);
		if (len < 0) {
			error = errno;
			if (fdp != NULL)
				_sandbox_dispose_rights(fdp, *fdcountp);
			free(buffer);
			return (-1);
		}
		if (len == 0) {
			errno = EPIPE;
			if (fdp != NULL)
				_sandbox_dispose_rights(fdp, *fdcountp);
			free(buffer);
			return (-1);
		}
		totlen += len;
	}
	*bufferp = buffer;
	*lenp = totlen;
	*opnop = req_hdr.sandboxrpc_reqhdr_opno;
	*seqnop = req_hdr.sandboxrpc_reqhdr_seqno;
	return (0);
}

int
sandbox_recvrpc(struct sandbox_cb *scb, u_int32_t *opnop, u_int32_t *seqnop,
    u_char **bufferp, size_t *lenp)
{

	return (sandbox_recvrpc_internal(scb, opnop, seqnop, bufferp, lenp,
	    NULL, NULL));
}

int
sandbox_recvrpc_rights(struct sandbox_cb *scb, u_int32_t *opnop, u_int32_t *seqnop,
    u_char **bufferp, size_t *lenp, int *fdp, int *fdcountp)
{

	return (sandbox_recvrpc_internal(scb, opnop, seqnop, bufferp, lenp,
	    fdp, fdcountp));
}

static int
sandbox_sendrpc_internal(struct sandbox_cb *scb, u_int32_t opno, u_int32_t seqno,
    struct iovec *rep, int repcount, int *fdp, int fdcount)
{
	struct sandboxrpc_reply_hdr rep_hdr;
	ssize_t len;
	int i;

	bzero(&rep_hdr, sizeof(rep_hdr));
	rep_hdr.sandboxrpc_rephdr_magic = SANDBOX_RPC_REPLY_HDR_MAGIC;
	rep_hdr.sandboxrpc_rephdr_seqno = seqno;
	rep_hdr.sandboxrpc_rephdr_opno = opno;
	rep_hdr.sandboxrpc_rephdr_datalen = 0;
	for (i = 0; i < repcount; i++)
		rep_hdr.sandboxrpc_rephdr_datalen += rep[i].iov_len;

	/*
	 * Send our header.
	 */
	if (fdp != NULL)
		len = _sandbox_rpc_send_rights(scb->fd_sandbox_end, &rep_hdr,
			sizeof(rep_hdr), 0, fdp, fdcount);
	else
		len = _sandbox_rpc_send(scb->fd_sandbox_end, &rep_hdr, sizeof(rep_hdr), 0);
	if (len < 0)
		return (-1);
	if (len != sizeof(rep_hdr)) {
		errno = EPIPE;
		return (-1);
	}

	/*
	 * Send user data.
	 */
	for (i = 0; i < repcount; i++) {
		len = _sandbox_rpc_send(scb->fd_sandbox_end, rep[i].iov_base,
		    rep[i].iov_len, 0);
		if (len < 0)
			return (-1);
		if ((size_t)len != rep[i].iov_len) {
			errno = EPIPE;
			return (-1);
		}
	}
	return (0);
}

int
sandbox_sendrpc(struct sandbox_cb *scb, u_int32_t opno, u_int32_t seqno,
    struct iovec *rep, int repcount)
{

	return (sandbox_sendrpc_internal(scb, opno, seqno, rep, repcount, NULL,
	    0));
}

int
sandbox_sendrpc_rights(struct sandbox_cb *scb, u_int32_t opno, u_int32_t seqno,
    struct iovec *rep, int repcount, int *fdp, int fdcount)
{

	return (sandbox_sendrpc_internal(scb, opno, seqno, rep, repcount, fdp,
	    fdcount));
}
