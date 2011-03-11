from mod_python import Cookie
import scs

# SCS wrapper for mod_python
class ModPyScs:

    # Wrapper for SCS constructor
    def __init__(self, req, 
            tid='tid',
            cipher=0,
            key='k',
            hkey='hk',
            comp=0,
            maxage=500):    # 5 minutes

        # initialise SCS parameters
        self.s = scs.init(tid, cipher, key, hkey, comp, maxage)
        if self.s is None:
            raise Exception

        self.req = req            

    # Wrapper for SCS destructor
    def __del__(self):

        if self.s:
            scs.term(self.s)
            
    # Get value of SCS variable 'var'
    def get(self, var):

        cookies = Cookie.get_cookies(self.req)
        if cookies is None:
            return None

        cookie = cookies.get(var, None)
        if cookie is None:
            return None

        val = cookie.value

        st = scs.decode(self.s, val)
        if st is None:
            raise Exception, 'failed scs.decode()'

        return st

    # Set SCS variable 'var' to 'val'             
    def set(self, var, val):

        ck = scs.encode(self.s, val, len(val))
        if ck is None:
            raise Exception, 'failed scs.encode()'
       
        c = Cookie.Cookie(var, ck)
        Cookie.add_cookie(self.req, c)
        
        return ck

    # Return SCS error string
    def err(self):
            
        return scs.err(self.s) 
