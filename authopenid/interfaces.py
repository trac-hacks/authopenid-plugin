from trac.core import Interface

class IOpenIDExtensionProvider(Interface):
    """ Provides support for requesting information via OpenID extensions.
    """

    def add_to_auth_request(req, auth_request):
        """ Modify auth_request to make desired extension request.

        FIXME: can we get rid of the ``req`` argument?
        """

    def parse_response(response):
        """ Parse the response.

        Returns a dict whose keys may include ``'email'``, ``'fullname'``,
        and ``'nickname'``.

        XXX: May raise an exception if authentication should not be
        allowed to proceed.
        """

class IAuthorizationProvider(Interface):
    """ Provides support for authorizing OpenID users.

    """

    def authorize(claimed_identifier, extension_data=None):
        """ Determine with user is authorized to log in.

        Raises ``NotAuthorized`` if not authorized.  Note that if
        any of the enabled authorization providers raises and exception,
        the user will not be allowed to log in.
        """

class IOpenIDConsumer(Interface):
    def begin(req, identifier, return_to):
        """ Start the openid authentication process.
        """

    def complete(req):
        """ Process authentication response.
        """

class IUserLogin(Interface):
    def login(req, username, referer=None):
        """ Log the user in as ``username`` and redirect to ``referer``

        The current session must be anonymous.
        """

    def logout(req, referer=None):
        """ Log the user out and redirect to ``referer``
        """
