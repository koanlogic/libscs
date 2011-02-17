include common.mk
include ../Makefile.conf

LIB = scs
SHLIB = yes

SRCS = scs.c
SRCS += utils.c
SRCS += base64.c
ifdef USE_CYASSL
SRCS += cyassl_drv.c 
endif   # USE_CYASSL
ifdef USE_OPENSSL
SRCS += openssl_drv.c 
endif   # USE_OPENSSL

include lib.mk
