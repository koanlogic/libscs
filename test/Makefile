include common.mk
include ../Makefile.conf

PROG = scs
SRCS = main.c
LDADD = $(SRCDIR)/src/libscs.a

include prog.mk

all-hook-post: ; @sh run-tests.sh
