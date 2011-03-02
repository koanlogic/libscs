include common.mk

SUBDIR = src
SUBDIR += test
SUBDIR += include

include subdir.mk

# special post actions for the 'distclean' target
DISTCLEANFILES = Makefile.conf include/scs_conf.h
distclean-post: ; rm -f $(DISTCLEANFILES)
