#!/bin/sh

SCSBIN="`pwd`/scs"

#OF=/dev/null
OF=/dev/stdout

err ()
{
    echo $*
    exit 1
}

test0 ()
{
    # Encode/Decode with all automatic parameters.

    "${SCSBIN}" -A > "${OF}"
}

test1 ()
{
    # Encode/Decode with all automatic parameters but the state string.

    "${SCSBIN}" -A \
                -s "try to encode and decode my custom state" \
        > "${OF}"
}

test2 ()
{
    # Encode/Decode with all automatic parameters but the state string, and
    # HMAC and encryption keys.

    "${SCSBIN}" -A \
                -s "yet another custom state string" \
                -k "0123456789abcdef" \
                -h "12345678901234567890" \
        > "${OF}"
}

test3 ()
{
    # Encode/Decode with all custom parameters.

    "${SCSBIN}" -A \
                -s "my state" \
                -k "fedcba9876543210" \
                -h "09876543210987654321" \
                -t my_tid \
        > "${OF}"
}

test4 ()
{
    # Encode/Decode from file using compression.

    "${SCSBIN}" -A \
                -d \
                -z \
                -f book.json \
                -o book-decoded.json
        > "${OF}"

    diff book.json book-decoded.json 
    ret=$?
    [ $ret = 0 ] && rm -f book-decoded.json
    return $ret
}

#
# Run tests.
#
test0 || err "test0"
test1 || err "test1"
test2 || err "test2"
test3 || err "test3"
test4 || err "test4"
# ...

echo ">> all tests ok"
