export makl_conf_h="include/scs_conf.h"

. "${MAKL_DIR}/cf/makl.init"
makl_args_init "$@"

# Source option hooks.
. build/opt_crypto
. build/opt_gnu_debug

# libscs-x.y.z
makl_pkg_name "libscs"
makl_pkg_version

target=`makl_target_name`
case ${target} in
    *darwin*)
        makl_set_var "OS_DARWIN"
        ;;
    *linux*)
        makl_set_var "OS_LINUX"
        ;;
esac

# Some handy CC flags.
makl_add_var_mk "SRCDIR" "`pwd`"
makl_add_var_mk "CFLAGS" "-I\$(SRCDIR)/include"
makl_add_var_mk "CFLAGS" "-W -Wall -Wextra"

# Third party library dependencies (i.e. libz + a suitable crypto library).
makl_optional 1 "lib" "z" "" "-lz"
makl_add_var_mk "CFLAGS" "\$(LIBZ_CFLAGS)"
makl_add_var_mk "LDFLAGS" "\$(LIBZ_LDFLAGS)"

# After user supplied arguments have been parsed, we'll check whether the
# requested crypto toolkit has been found.
makl_optional 1 "lib" "openssl" "" "-lssl -lcrypto"

CYASSL_BASE="/usr/local/cyassl"
makl_optional 1 "lib" "cyassl" \
                  "-I${CYASSL_BASE}/include" "-L${CYASSL_BASE}/lib -lcyassl"

#
# Handle command line arguments.
#
makl_args_handle "$@"

# Now check if we have found the requested crypto library.
if [ "`makl_get_var_mk "USE_OPENSSL"`" ]
then
    [ -z "`makl_get_var_mk "HAVE_LIBOPENSSL"`" ] && \
        makl_err 1 "Required OpenSSL not found !"
    makl_add_var_mk "CFLAGS" "\$(LIBOPENSSL_CFLAGS)"
    makl_add_var_mk "LDFLAGS" "\$(LIBOPENSSL_LDFLAGS)"
fi

if [ "`makl_get_var_mk "USE_CYASSL"`" ]
then
    [ -z "`makl_get_var_mk "HAVE_LIBCYASSL"`" ] && \
        makl_err 1 "Required CyaSSL not found !"
    makl_add_var_mk "CFLAGS" "\$(LIBCYASSL_CFLAGS)"
    makl_add_var_mk "LDFLAGS" "\$(LIBCYASSL_LDFLAGS)"
fi

# Send configuration to Makefile.conf and include/conf.h files.
. "${MAKL_DIR}/cf/makl.term"
