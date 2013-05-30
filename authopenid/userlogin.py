''' Helpers for creating and manipulating the trac "user database".
'''
from __future__ import absolute_import

from genshi.builder import tag
from trac.core import implements
from trac.web.chrome import INavigationContributor
from trac.web.main import IRequestHandler
from trac.web.auth import IAuthenticator, LoginModule

from authopenid.api import IUserLogin
from authopenid.compat import Component
from authopenid.util import sanitize_referer

## List of components which might provide a 'Logout' navagation link
_LOGIN_MODULES = [LoginModule]
try:
    from acct_mgr.web_ui import LoginModule as acct_mgr_LoginModule
    _LOGIN_MODULES.append(acct_mgr_LoginModule)
except ImportError:
    pass

class UserLogin(Component):
    """ Manages the actual logging-in of users (setting auth cookies), etc.

    We currently use ``trac.web.auth.LoginModule`` to manage the auth cookies.
    """

    implements(IAuthenticator, INavigationContributor, IRequestHandler,
               IUserLogin)

    def __init__(self):
        self.login_module = LoginModule(self.env)

    # INavigationContributor methods
    def get_active_navigation_item(self, req):
        return 'openid/logout'

    def get_navigation_items(self, req):
        # If other LoginModules are enabled, they'll provide this stuff
        if any(self.env.is_component_enabled(comp) for comp in _LOGIN_MODULES):
            return
        if req.authname and req.authname != 'anonymous':
            # FIXME: Add config to show name rather than sid (b/c)
            yield ('metanav', 'openid/login',
                   'logged in as %s' % req.authname)
            yield ('metanav', 'openid/logout',
                   tag.a('Logout', href=req.href.openid('logout')))

    # IRequestHandler methods
    def match_request(self, req):
        return req.path_info == '/openid/logout'

    def process_request(self, req):
        assert req.path_info == '/openid/logout'
        return self.logout(req)

    # IAuthenticator
    def authenticate(self, req):
        # We use the stock LoginModule to handle the authentication cookies
        return self.login_module.authenticate(req)


    def login(self, req, username, referer=None):
        """ Log user in

        Logs the user in as ``username``.

        An HTTP redirect is then performed to the url specified
        by the first available of:
        - the ``referer`` argument
        - the ``Referer`` HTTP request header
        - the top of the trac

        """
        assert req.authname == 'anonymous'

        # Ab(Use) LoginModule to set auth cookie

        referer = sanitize_referer(referer, req.base_url)
        if referer:
            req.args['referer'] = referer
        req.environ['REMOTE_USER'] = username
        req.environ['PATH_INFO'] = '/login'
        return self.login_module.process_request(req)

    def logout(self, req, referer=None):
        """ Log user out

        An HTTP redirect is then performed to the url specified
        by the first available of:
        - the ``referer`` argument
        - the ``Referer`` HTTP request header
        - the top of the trac

        """
        referer = sanitize_referer(referer, req.base_url)
        if referer:
            req.args['referer'] = referer
        req.environ['PATH_INFO'] = '/logout'
        return self.login_module.process_request(req)
