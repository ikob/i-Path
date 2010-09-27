#
# Makefile of SIRENS ping
#

PROG	= ping
OBJS	= ping.o
CC	= gcc
CFLAGS	= -g -Wall -Werror -DIPSIRENS
INSTALL	= install --mode=4755
INSTALL_DIR = /usr/local/bin

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $< -lm

install: $(PROG)
	$(INSTALL) $(PROG) $(INSTALL_DIR)/srping

clean:
	rm -f *.o $(PROG)
