include common.mk
include ../../Makefile.conf

LIB = scsmodule
SHLIB = true
SHLIB_NAME = _scsmodule.so

SRCS = $(SWIG_WRAP)

CFLAGS += $(shell python-config --cflags)
CFLAGS +=  $(LIBCYASSL_CFLAGS)
LDFLAGS += $(shell python-config --ldflags)
LDFLAGS += $(LIBCYASSL_LDFLAGS)

LDADD = ../../src/libscs.a

SWIG_CMD ?= swig
SWIG_WRAP = scsmodule_wrap.c
SWIG_IN = scsmodule.i

CLEANFILES += $(SWIG_WRAP)
CLEANFILES += *.py
CLEANFILES += *.pyc

include lib.mk

$(SWIG_WRAP):
	$(SWIG_CMD) -python $(SWIG_IN)

all-hook-pre: $(SWIG_WRAP)

install-hook-post:
	$(INSTALL) scs.py $(LIBDIR)
