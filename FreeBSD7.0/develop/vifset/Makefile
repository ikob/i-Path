CFLAGS	      = -I../../sys -I/usr/local/include

DEST	      = .

EXTHDRS	      =

HDRS	      =

INSTALL	      = cp

LD	      = $(CC)

LDFLAGS	      = -L/usr/local/lib

LIBS	      = -lconfig -lnetsnmp -lssl

MAKEFILE      = Makefile

OBJS	      = vifset.o

PRINT	      = pr

PROGRAM       = vifset

SHELL	      = /bin/sh

SRCS	      = vifset.c

SYSHDRS	      = 

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
