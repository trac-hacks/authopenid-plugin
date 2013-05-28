from __future__ import absolute_import

from trac.core import Interface
from genshi.builder import tag
from genshi.core import Markup

from openid.consumer.discover import DiscoveryFailure ; 'SIDE-EFFECTS'

from authopenid.util import MultiDict



FULL_NAME = 'openid.fullname'
EMAIL_ADDRESS = 'openid.email'
NICKNAME = 'openid.nickname'

class OpenIDException(Exception):
    def __html__(self):
        if len(self.args) > 0:
            message = self.args[0]
        else:
            message = self.__class__.__name__
        return Markup(message)

    def __unicode__(self):
        return unicode(self.__html__().striptags().stripentities())

    def __str__(self):
        return self.__unicode__().encode('utf-8')

class ExtensionResponseUnacceptable(OpenIDException):
    """ OpenID response is not acceptable here

    This exception is raised by extension providers to indicate that
    the OpenID response should not be used for authentication.

    """

class NotAuthorized(OpenIDException):
    """ User is not allowed here

    This exception is raised by authorization policies to indicate that
    user (identified by a successful OpenID authentication request) should
    not be allowed to log in.

    """

class NegativeAssertion(OpenIDException):
    """ OpenID authentication returned a negative assertion

    Subclasses of :exc:`NegativeAssertion` are raised by
    :meth:`OpenIDConsumer.complete` to indicate that the user could
    not be successfull authenticated.

    """

class AuthenticationCancelled(NegativeAssertion):
    """ The user cancelled the authentication process.

    Raised by :meth:`OpenIDConsumer.complete` to indicate that the
    user cancelled the OpenID authentication process.

    """
    def __html__(self):
        return Markup(str(self) or 'Authentication Cancelled')

class SetupNeeded(NegativeAssertion):
    """ Immediate authentication failed.

    Raised by :meth:`OpenIDConsumer.complete` in response to an
    'immediate' (non-interactive) authentication request to indicate
    that the user interaction (at the provider side) is required to
    complete authentication.

    """
    def __init__(self, setup_url=None):
        message = "Setup needed"
        if setup_url:
            message = tag.a(message, href=setup_url)
        super(SetupNeeded, self).__init__(message, setup_url)

    @property
    def setup_url(self):
        return self.args[1]

    def __html__(self):
        message = "Setup needed"
        if self.setup_url:
            message = tag.a(message, href=self.setup_url)
        return Markup(message)

class AuthenticationFailed(NegativeAssertion):
    """ OpenId Authentication failed.

    Raised by :meth:`OpenIDConsumer.complete` to indicate
    a failure of OpenID authentication.   This error indicates an
    protocol error (invalid request or response format, etc.) of some
    sort.  (It *does not* mean 'password didn't match'.)

    """
    def __init__(self, reason=None, identity_url=None):
        super(AuthenticationFailed, self).__init__(reason, identity_url)

    @property
    def reason(self):
        return self.args[0]

    @property
    def identity_url(self):
        return self.args[1]

    def __html__(self):
        message = tag("Authentication failed")
        if self.identity_url:
            message += tag(" for ", tag.code(self.identity_url))
        if self.reason:
            message += tag(": ", self.reason)
        return Markup(message)


class OpenIDIdentifier(str):
    """ Represents an OpenID identifier response as received from an OP

    This class represents the results of a successful OpenID authentication.

    Additionally, the ``OpenIDIdentifier`` has a (multi-valued)
    dictionary containing additional data (e.g. full name and/or email
    address as determined via SREG or AX, for example.)  Certain keys
    in this dictionary have pre-defined meanings:

    :const:`FULL_NAME`
        The user's full name

    :const:`EMAIL_ADDRESS`,
        The user's email address

    :const:`NICKNAME`
        The user's 'nickname' (or 'username')

    Additional data may also be stored in the ``signed_data`` dictionary
    by extension providers.   (Such data should use keys which do not
    begin with ``'openid.'``.)

    """
    def __init__(self, identifier):
        self.signed_data = MultiDict()

    @property
    def identifier(self):
        return str(self)


class IOpenIDExtensionProvider(Interface):
    """ Provides support for requesting information via OpenID extensions.
    """

    def add_to_auth_request(req, auth_request):
        """ Modify auth_request to make desired extension request.

        :type req: :class:`trac.web.api.Request`
        :type auth_request: :class:`openid.consumer.consumer.AuthRequest`

        """

    def parse_response(response, oid_identifier):
        """ Parse the response.

        This should extract any information of interest from extension
        fields in the OpenID id_res response and insert it into the
        ``signed_data`` multidict on the ``oid_identifier``.

        Generally any data should be appended to that already in the
        ``signed_data`` dict (using :meth:``MultiDict.add``).  That way
        data provider by earlier extension providers will take precedence
        over that provided by later ones.

        Only data which comes from signed response fields should be
        placed into the ``signed_data`` dict.

        :type response: :class:`openid.consumer.consumer.SuccessResponse`
        :type oid_identifier: :class:`OpenIDIdentifier`

        :raises: :exc:`ExtensionResponseUnacceptable` if the data
            returned via the openid extension indicates that the
            entire OpenID response is not acceptable for use in
            authentication.  (This can be used, for example, to
            enforce the required use of certain PAPE authentication
            policies.)

        """

class IOpenIDAuthorizationPolicy(Interface):
    """ Provides support for authorizing OpenID users.

    An authorization policy checks the user's identity (as returned
    by a successful OpenID authentication request) to determine whether
    log-in should be allowed to proceed.

    """

    def authorize(identifier):
        """ Determine with user is authorized to log in.

        All of the configured authorization policies will be called to
        check whether the user is authorized to use this site.  If any
        of the policies raises :exc:`NotAuthorized`, or if no policy
        returns a true value, authorization will be denied; otherwise if
        any of the policies returns a true value, access will be granted.

        :type identifier: :class:`IOpenIDIdentifier`

        :returns: True if the user is authorized.  If the policy returns
            ``False``, it does not make any particular claims about the
            authorization of the user.

        :raises: :exc:`NotAuthorized` if the user is not authorized

        """
