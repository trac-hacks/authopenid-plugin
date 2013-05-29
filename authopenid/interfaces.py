# -*- coding: utf-8 -*-
from trac.core import Interface


class IOpenIDConsumer(Interface):
    def begin(req, identifier, return_to):
        """ Start the openid authentication process.

        If successful, a redirect is issued, either via HTTP redirect
        or via an auto-submitting HTML form response.  In either of these
        cases, this method is a 'no return' — it exists by raising
        a :exc:`trac.web.api.RequestDone` exception.

        :raises: :exc:`DiscoveryFailure`
        :raises: :exc:`trac.web.api.RequestDone`
            This is the _normal exit_ for the method.
        """

    def complete(req):
        """ Process authentication response.

        This handles the _indirect response_ to an OpenID authentication
        request.


        :rtype: :class:`OpenIDIndentifier`

        :raises: :exc:`AuthenticationCancelled`
        :raises: :exc:`SetupNeeded`
        :raises: :exc:`AuthenticationFailed`
        :raises: :exc:`ExtensionResponseUnacceptable`
        """

class IUserLogin(Interface):
    def login(req, username, referer=None):
        """ Log the user in as ``username`` and redirect to ``referer``

        The current session must be anonymous.
        """

    def logout(req, referer=None):
        """ Log the user out and redirect to ``referer``
        """
