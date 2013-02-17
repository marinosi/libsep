#
# $FreeBSD: releng/9.1/tools/tools/netmap/Makefile 231650 2012-02-14 09:42:02Z luigi $
#
# For multiple programs using a single source file each,
# we can just define 'progs' and create custom targets.
CC		?=	clang
LIBS 	=	libsep.so
OBJS	=	*.o

CLEANFILES = $(LIBS) $(OBJS)
NO_MAN=
CFLAGS += -Werror -Wall 
CFLAGS += -Wextra

LDFLAGS +=

.include <bsd.prog.mk>
.include <bsd.lib.mk>

all: libsep.so

libsep.so:	sandbox.c sandbox_rpc.c
	$(CC) $(CFLAGS) -fpic -c ${.ALLSRC}
	$(CC) -shared -o ${.TARGET} ${.ALLSRC:.c=.o}
