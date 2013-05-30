''' Helpers for creating and manipulating the trac "user database".
'''
from __future__ import absolute_import

from trac.core import implements
from trac.web.auth import IAuthenticator, LoginModule

from authopenid.api import IUserLogin
from authopenid.compat import Component
from authopenid.util import sanitize_referer

class UserLogin(Component):
    """ Manages the actual logging-in of users (setting auth cookies), etc.

    We currently use ``trac.web.auth.LoginModule`` to manage the auth cookies.
    """

    implements(IAuthenticator, IUserLogin)

    def __init__(self):
        self.login_module = LoginModule(self.env)

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
