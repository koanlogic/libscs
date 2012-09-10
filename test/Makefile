include common.mk
include ../Makefile.conf

PROG = scs
SRCS = main.c
LDADD = $(SRCDIR)/src/libscs.a

include prog.mk

all-hook-post: ; @sh run-tests.sh

SCS_ARGS = -t tid -h 12345678901234567890 -k 0123456789abcdef

valgrind: $(PROG)
	@rm -rf $(PROG).dSYM && /usr/bin/dsymutil ./$(PROG)
	@valgrind --leak-check=full \
              --track-origins=yes \
              --dsymutil=yes \
              ./$(PROG) $(SCS_ARGS)

