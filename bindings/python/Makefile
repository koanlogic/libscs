include common.mk
include ../../Makefile.conf

ifndef HAVE_SWIG
  $(error Must have swig to build binding! Install and rerun configuration.)
endif
ifndef HAVE_PYTHON
  $(error Must have python to build binding! Install and rerun configuration.)
endif

LIB = scsmodule
SHLIB = true
SHLIB_NAME = _scsmodule.so

# not a standard lib install - only $(SWIG_OUT) and $(SHLIB_NAME)
# are installed in python site package directory
NO_INSTALL = yes

SRCS = $(SWIG_WRAP)

# python flags
CFLAGS += $(shell $(PATH_PYTHON)-config --cflags)
LDFLAGS += $(shell $(PATH_PYTHON)-config --ldflags)

# cyassl flags
CFLAGS += $(LIBCYASSL_CFLAGS)
LDFLAGS += $(LIBCYASSL_LDFLAGS)

# scs flags
LDFLAGS += -L$(LIBDIR) -lscs

# swig files
SWIG_WRAP = scsmodule_wrap.c
SWIG_IN = scsmodule.i
SWIG_OUT = scs.py

# mod_pytho wrapper
MODPY_WRAP = modpyscs.py

# get site package dir directly from python
PY_SITEDIR=$(shell $(PATH_PYTHON) -c \
	"from distutils.sysconfig import get_python_lib;\
	print get_python_lib()")

CLEANFILES += $(SWIG_WRAP)
CLEANFILES += $(SWIG_OUT)
CLEANFILES += scs.pyc

include lib.mk

$(SWIG_WRAP): $(SWIG_IN)
	$(PATH_SWIG) -python $(SWIG_IN)

all-hook-pre: $(SWIG_WRAP)

install:
	$(INSTALL) $(SWIG_OUT) \
        $(SHLIB_NAME) \
        $(MODPY_WRAP) \
        $(PY_SITEDIR)
