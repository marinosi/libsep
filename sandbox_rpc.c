#include <sys/socket.h>

#include <fcntl.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "sandbox_rpc.h"

void
_sandbox_dispose_rights(int *fdp, int fdcount)
{
	int i;

	for (i = 0; i < fdcount; i++)
		close(fdp[i]);
}

/*
 * Given a 'struct msghdr' returned by a successful call to recvmsg(),
 * extract up to the desired number of file descriptors (or clean up the
 * mess if something goes wrong).
 */
int
_sandbox_rpc_receive_rights(struct msghdr *msg, int *fdp, int *fdcountp)
{
	int *cmsg_fdp, fdcount, i, scmrightscount;
	struct cmsghdr *cmsg;

	/*
	 * Walk the complete control message chain to count received control
	 * messages and rights.  If there is more than one rights message or
	 * there are too many file descriptors, re-walk and close them all
	 * and return an error.
	 */
	fdcount = 0;
	scmrightscount = 0;
	for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL;
	    cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (cmsg->cmsg_level != SOL_SOCKET ||
		    cmsg->cmsg_type != SCM_RIGHTS)
			continue;
		fdcount += (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
		scmrightscount++;
	}
	if (scmrightscount > 1 || fdcount > *fdcountp) {
		for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL;
		    cmsg = CMSG_NXTHDR(msg, cmsg)) {
			if (cmsg->cmsg_level != SOL_SOCKET ||
			    cmsg->cmsg_type != SCM_RIGHTS)
				continue;
			cmsg_fdp = (int *)(void *)CMSG_DATA(cmsg);
			fdcount = (cmsg->cmsg_len - CMSG_LEN(0)) /
			    sizeof(int);
			_sandbox_dispose_rights(cmsg_fdp, fdcount);
		}
		errno = EBADMSG;
		return (-1);
	}

	/*
	 * Re-walk the control messages and copy out the file descriptor
	 * numbers, return success.  No need to recalculate fdcount.
	 */
	for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL;
	    cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (cmsg->cmsg_level != SOL_SOCKET ||
		    cmsg->cmsg_type != SCM_RIGHTS)
			continue;
		cmsg_fdp = (int *)(void *)CMSG_DATA(cmsg);
		for (i = 0; i < fdcount; i++)
			fdp[i] = cmsg_fdp[i];
	}
	*fdcountp = fdcount;
	return (0);
}

ssize_t
_sandbox_rpc_send(int fd, const void *msg, size_t len, int flags)
{
	ssize_t retlen;

	if (fd == -1 || fd == 0) {
		errno = ECHILD;
		return (-1);
	}

	do {
		retlen = send(fd, msg, len, flags);
	} while (retlen < 0 && errno == EINTR);

	return (retlen);
}

#define SANDBOX_RPC_API_MAXRIGHTS 16
ssize_t
_sandbox_rpc_send_rights(int fd, const void *msg, size_t len, int flags, int
	*fdp, int fdcount)
{
	char cmsgbuf[CMSG_SPACE(SANDBOX_RPC_API_MAXRIGHTS * sizeof(int))];
	struct cmsghdr *cmsg;
	struct msghdr msghdr;
	struct iovec iov;
	ssize_t retlen;
	int i;

	if (fdcount == 0)
		return (_sandbox_rpc_send(fd, msg, len, flags));

	if (fd == -1 || fd == 0) {
		errno = ECHILD;
		return (-1);
	}

	bzero(&iov, sizeof(iov));
	iov.iov_base = __DECONST(void *, msg);
	iov.iov_len = len;

	bzero(&cmsgbuf, sizeof(cmsgbuf));
	cmsg = (struct cmsghdr *)(void *)cmsgbuf;
	cmsg->cmsg_len = CMSG_SPACE(fdcount * sizeof(int));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	for (i = 0; i < fdcount; i++)
		((int *)(void *)CMSG_DATA(cmsg))[i] = fdp[i];

	bzero(&msghdr, sizeof(msghdr));
	msghdr.msg_iov = &iov;
	msghdr.msg_iovlen = 1;
	msghdr.msg_control = cmsg;
	msghdr.msg_controllen = cmsg->cmsg_len;

	/* Ignore EINTR */
	do {
		retlen = sendmsg(fd, &msghdr, flags);
	} while (retlen < 0 && errno == EINTR);

	return (retlen);
}

#include <stdio.h>
ssize_t
_sandbox_rpc_recv(int fd, void *buf, size_t len, int flags)
{
	ssize_t retlen;

	if (fd == -1 || fd == 0) {
		errno = ESRCH;
		return (-1);
	}

	do {
		retlen = recv(fd, buf, len, flags);
	} while (retlen < 0 && errno == EINTR);

	/* This is for non blocking file descriptors */
	if (errno == EAGAIN) {
		retlen = 0;
	}

	return (retlen);
}

ssize_t
_sandbox_rpc_recv_nonblock(int fd, void *buf, size_t len, int flags)
{
	ssize_t retlen = 0;
	fd_set	rset;
	struct timeval tv;
	ssize_t ret;

	if(fd == -1 || fd == 0) {
		errno = ESRCH;
		return (-1);
	}

	FD_ZERO(&rset);
	FD_SET(fd, &rset);
	tv.tv_sec = 0;
	tv.tv_usec = 100;

	ret = select(fd+1, &rset, NULL, NULL, &tv);
	if (ret > 0) {
		do {
			retlen = recv(fd, buf, len, flags | MSG_WAITALL);

		} while (retlen < 0 && errno == EINTR);

		if (errno == EAGAIN)
			retlen = 0;
	}

	return (retlen);
}

#define SANDBOX_RPC_API_MAXRIGHTS 16
ssize_t
_sandbox_rpc_recv_rights(int fd, void *buf, size_t len, int flags, int *fdp,
	int *fdcountp)
{
	char cmsgbuf[CMSG_SPACE(SANDBOX_RPC_API_MAXRIGHTS * sizeof(int))];
	struct msghdr msghdr;
	struct iovec iov;
	ssize_t retlen;

	if (*fdcountp == 0)
		return (_sandbox_rpc_recv(fd, buf, len, flags));

	if (fd == -1 || fd == 0) {
		errno = ECHILD;
		return (-1);
	}

	if (*fdcountp > SANDBOX_RPC_API_MAXRIGHTS) {
		errno = EMSGSIZE;
		return (-1);
	}

	bzero(&iov, sizeof(iov));
	iov.iov_base = buf;
	iov.iov_len = len;

	bzero(cmsgbuf, sizeof(cmsgbuf));
	bzero(&msghdr, sizeof(msghdr));
	msghdr.msg_iov = &iov;
	msghdr.msg_iovlen = 1;
	msghdr.msg_control = cmsgbuf;
	msghdr.msg_controllen = sizeof(cmsgbuf);

	do {
		retlen = recvmsg(fd, &msghdr, flags);
	} while (retlen < 0 && errno == EINTR);

	if (retlen < 0)
		return (-1);
	if (_sandbox_rpc_receive_rights(&msghdr, fdp, fdcountp) < 0)
		return (-1);
	return (retlen);
}

