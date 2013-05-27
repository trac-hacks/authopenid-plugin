''' Helpers for creating and manipulating the trac "user database".
'''
from __future__ import absolute_import

from trac.core import Component, implements
from trac.web.auth import IAuthenticator, LoginModule
from trac.web.session import DetachedSession

from authopenid.exceptions import IdentifierNotUnique, UserExists
from authopenid.util import sanitize_referer

class UserManager(Component):
    """ Helper for managing trac 'user accounts'

    In trac, 'user accounts' are intertwingled with the session database.
    'User account' translates rougly to 'authenticate sessions'.

    """

    openid_identifier_skey = 'openid_session_identity_url_data'

    def create_user(self, username, openid_identifier=None, attributes=None):
        """ Create a new user in trac's session database

        Create a new authenticated session with SID specified by
        ``username``.  The initial session attributes will be set to
        ``attributes`` (if given.)

        Raises ``UserExists`` if an authenticated session already
        exists with the given SID.
        """
        if openid_identifier:
            attributes = dict(attributes or ())
            attributes[self.openid_identifier_skey] = openid_identifier

        if LoginModule(self.env).ignore_case:
            username = username.lower()

        with self.env.db_transaction as db:
            (exists,), = db("SELECT COUNT(*) FROM session WHERE sid=%s",
                            (username,))
            if exists:
                raise UserExists(
                    "A session with sid %r already exists" % username)

            db("INSERT INTO session (sid, authenticated, last_visit)"
               " VALUES (%s, 1, 0)", (username,))

            session = DetachedSession(self.env, username)
            session.clear()
            if attributes:
                session.update(attributes)
            session.save()


    def get_username(self, openid_identifier):
        """ Look up username by OpenID identifier

        FIXME: If multiple matches return the most recent logged in.
        Probably should provide a config option which controls whether
        multiple matches is an error or not.

        Returns username (sid) or ``None``.
        """
        with self.env.db_query as db:
            sids = db("SELECT sid FROM session_attribute"
                      " WHERE authenticated=%s AND name=%s AND value=%s",
                      (1, self.openid_identifier_skey, openid_identifier))
            if sids:
                if len(sids) > 1:
                    raise IdentifierNotUnique(
                        "Multiple users share the OpenID identifier: %r"
                        % [sid for sid, in sids])
                return sids[0][0]
        return None

class UserLogin(Component):
    """ Manages the actual logging-in of users (setting auth cookies), etc.

    We currently use ``trac.web.auth.LoginModule`` to manage the auth cookies.
    """

    implements(IAuthenticator)

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
