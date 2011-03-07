#!/usr/bin/python
#
# Very basic sample scs module usage

import scs


# encode/decode check
def test(str):
    print 'input state: [', str, ']'

    ck = scs.scs_encode(s, str, len(str))
    if ck is None:
        print '[err]: ', scs.scs_err(s), 
        raise Exception
        
    print 'encoded cookie: [', ck, ']'

    st = scs.scs_decode(s, ck)
    if st is None:
        print '[err]: ', scs.scs_err(s), 
        raise Exception

    print 'decoded state: [', st, ']'

    if st != str:
        print '[err] input state different from decoded state!'
        raise Exception


# Run tests
s = None

try:
    
    # initialise SCS parameters
    s = scs.scs_init(
            'tid', 
            0, 
            'k', 
            'hk', 
            0, 
            0);

    size = 0

    # basic encoding/decoding tests
    test('some cool state 1')
    test('some other state 2')

    # test key refresh
    scs.scs_refresh_keyset(s, 'tid2', 'k2', 'hk2')

    test('some other cool state 3 after key refresh')

    # cleanup
    scs.scs_term(s)

    print 'All tests passed.'

except Exception:

    # cleanup
    if s != None:
        scs.scs_term(s)

    print 'Failure in tests!'

