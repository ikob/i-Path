CFLAGS	      = -I../../sys

DEST	      = .

EXTHDRS	      =

HDRS	      =

INSTALL	      = cp

LD	      = $(CC)

LDFLAGS	      =

LIBS	      =

MAKEFILE      = Makefile

OBJS	      = prove.o

PRINT	      = pr

PROGRAM       = prove

SHELL	      = /bin/sh

SRCS	      = prove.c

SYSHDRS	      = /usr/include/machine/_limits.h \
		/usr/include/machine/_types.h \
		/usr/include/machine/endian.h \
		/usr/include/machine/param.h \
		/usr/include/machine/signal.h \
		/usr/include/machine/trap.h \
		/usr/include/netdb.h \
		/usr/include/netinet/in.h \
		/usr/include/netinet6/in6.h \
		/usr/include/stdlib.h \
		/usr/include/strings.h \
		/usr/include/sys/_iovec.h \
		/usr/include/sys/_null.h \
		/usr/include/sys/_pthreadtypes.h \
		/usr/include/sys/_sigset.h \
		/usr/include/sys/_timeval.h \
		/usr/include/sys/_types.h \
		/usr/include/sys/cdefs.h \
		/usr/include/sys/errno.h \
		/usr/include/sys/limits.h \
		/usr/include/sys/param.h \
		/usr/include/sys/priority.h \
		/usr/include/sys/select.h \
		/usr/include/sys/signal.h \
		/usr/include/sys/socket.h \
		/usr/include/sys/syslimits.h \
		/usr/include/sys/time.h \
		/usr/include/sys/timespec.h \
		/usr/include/sys/types.h \
		/usr/include/time.h

all:		$(PROGRAM)

$(PROGRAM):     $(OBJS) $(LIBS)
		@echo "Linking $(PROGRAM) ..."
		@$(LD) $(LDFLAGS) $(OBJS) $(LIBS) -o $(PROGRAM)
		@echo "done"

clean:;		@rm -f $(OBJS) core

clobber:;	@rm -f $(OBJS) $(PROGRAM) core tags

depend:;	@mkmf -f $(MAKEFILE)

echo:;		@echo $(HDRS) $(SRCS)

index:;		@ctags -wx $(HDRS) $(SRCS)

install:	$(PROGRAM)
		@echo Installing $(PROGRAM) in $(DEST)
		@-strip $(PROGRAM)
		@if [ $(DEST) != . ]; then \
		(rm -f $(DEST)/$(PROGRAM); $(INSTALL) $(PROGRAM) $(DEST)); fi

print:;		@$(PRINT) $(HDRS) $(SRCS)

tags:           $(HDRS) $(SRCS); @ctags $(HDRS) $(SRCS)
###
prove.o: /usr/include/stdlib.h /usr/include/sys/cdefs.h \
	/usr/include/sys/_null.h /usr/include/sys/_types.h \
	/usr/include/machine/_types.h /usr/include/strings.h \
	/usr/include/sys/types.h /usr/include/machine/endian.h \
	/usr/include/sys/_pthreadtypes.h /usr/include/sys/select.h \
	/usr/include/sys/_sigset.h /usr/include/sys/_timeval.h \
	/usr/include/sys/timespec.h /usr/include/sys/socket.h \
	/usr/include/sys/_iovec.h /usr/include/machine/param.h \
	/usr/include/sys/param.h /usr/include/sys/syslimits.h \
	/usr/include/sys/errno.h /usr/include/sys/time.h /usr/include/time.h \
	/usr/include/sys/priority.h /usr/include/sys/signal.h \
	/usr/include/machine/_limits.h /usr/include/machine/signal.h \
	/usr/include/machine/trap.h /usr/include/sys/limits.h \
	/usr/include/netinet/in.h /usr/include/netinet6/in6.h \
	/usr/include/netdb.h
