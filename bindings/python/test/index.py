from mod_python import apache
from modpyscs import ModPyScs
import time


def index(req):

    try: 
        req.content_type = "text/html"

        # default cookie impl (mod_python)
        s = ModPyScs(req)

        var_name = "cur_time"
        var_val = time.ctime()
        
        prev_val = s.get(var_name)
        if prev_val is None:
            prev_val = 'No previous state name: ', var_name
        
        cookie_val = s.set(var_name, var_val)
        if cookie_val is None:
            cookie_val = 'bad cookie'

        page="""
<html>
<body>
<h1>SCS Client-Side Sesssions Test Page</h1>
<br>
<b>variable name</b>: %s<br>
<b>variable value</b>: %s<br>
<b>previous value</b>: %s<br>
<br>
<b>encoded cookie cookie value</b>:<br>
%s<br>
</body>
</html>
""" % (var_name, var_val, prev_val, cookie_val)

        return page

    except Exception, e:

        req.content_type = "text/html"
        return 'An exception occurred: %s! (scs_err: %s)' % (str(e), s.err())

