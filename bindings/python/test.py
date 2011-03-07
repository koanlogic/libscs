#!/usr/bin/python
#
# Very basic sample scs module usage

import scs

s = scs.scs_init(
        'tid', 
        0, 
        'k', 
        'hk', 
        0, 
        0);

size = 0

str = 'some cool state'
print 'input state: [', str, ']'

ck = scs.scs_encode(s, str, len(str))
print 'encoded cookie: [', ck, ']'

st = scs.scs_decode(s, ck)

if st is None:
    print 'err: [', scs.scs_err(s), ']'
else:
    print 'decoded state: [', st, ']'

scs.scs_term(s)
