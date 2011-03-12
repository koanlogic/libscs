#!/bin/sh

SCSBIN="`pwd`/scs"

err ()
{
    echo $*
    exit 1
}

test0 ()
{
    "${SCSBIN}" -A > /dev/null
}

test1 ()
{
    "${SCSBIN}" -A \
                -s "try to encode and decode my custom state" \
        > /dev/null
}

test2 ()
{
    "${SCSBIN}" -A \
                -s "yet another custom state string" \
                -k "0123" \
                -h "4567" \
        > /dev/null
}

test3 ()
{
    "${SCSBIN}" -A \
                -s "my state" \
                -k "0123" \
                -h "4567" \
                -t my_tid \
        > /dev/null
}

test4 ()
{
    "${SCSBIN}" -A \
                -d \
                -z \
                -f book.json \
                -o book-decoded.json
        > /dev/null

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
