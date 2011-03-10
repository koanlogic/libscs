include common.mk
include Makefile.conf

SUBDIR = src
SUBDIR += test
SUBDIR += include

ifdef HAVE_DOXYGEN
SUBDIR += doxy
endif

include subdir.mk

# special post actions for the 'distclean' target
DISTCLEANFILES = Makefile.conf include/scs_conf.h
distclean-post: ; rm -f $(DISTCLEANFILES)
