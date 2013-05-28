from trac.core import Interface


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
