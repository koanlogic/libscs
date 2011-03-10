include common.mk
include ../Makefile.conf

DOXYFILE = libscs.doxy

ifdef HAVE_DOXYGEN

all: ; $(PATH_DOXYGEN) $(DOXYFILE)

install uninstall: ; echo TODO un/install targets in doxy

clean: ; $(RM) -rf html man

else    # !HAVE_DOXYGEN

all clean install uninstall:

endif   # HAVE_DOXYGEN

depend cleandepend distclean:
