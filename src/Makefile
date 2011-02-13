include common.mk
include ../Makefile.conf

LIB = scs
SRCS = scs.c
SRCS += base64.c
ifdef USE_CYASSL
SRCS += cyassl_drv.c 
endif

include lib.mk
