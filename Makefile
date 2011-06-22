include common.mk
include Makefile.conf

SUBDIR = src

ifdef HAVE_DOXYGEN
SUBDIR += doxy
endif

SUBDIR += include
SUBDIR += test

include subdir.mk

# special post actions for the 'distclean' target
DISTCLEANFILES = Makefile.conf include/scs_conf.h
distclean-post: ; rm -f $(DISTCLEANFILES)
