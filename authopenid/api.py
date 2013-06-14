# -*- coding: utf-8 -*-
from __future__ import absolute_import

from trac.core import Interface
from genshi.builder import tag
from genshi.core import escape

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
        return escape(message)

    def __unicode__(self):
        return unicode(self.__html__().striptags().stripentities())

    def __str__(self):
        return self.__unicode__().encode('utf-8')

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

class AuthenticationFailed(NegativeAssertion):
    """ OpenId Authentication failed.

    Raised by :meth:`OpenIDConsumer.complete` to indicate
    a failure of OpenID authentication.   This error indicates an
    protocol error (invalid request or response format, etc.) of some
    sort.  (It *does not* mean 'password didn't match'.)

    """
    def __init__(self, reason=None, identity_url=None):
        msg = tag("Authentication failed")
        if identity_url:
            msg += tag(" for ", tag.code(identity_url))
        if reason:
            msg += tag(": ", reason)
        super(AuthenticationFailed, self).__init__(msg, reason, identity_url)

    @property
    def reason(self):
        return self.args[1]

    @property
    def identity_url(self):
        return self.args[2]

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


# FIXME: rename to *Participant
class IOpenIDAuthnRequestListener(Interface):
    """ Components implementing :class:`IOpenIDAuthnRequestListener`
    can participate in the OpenID checkid requests.

    These components can, e.g., make requests for extra information
    from the OP via OpenID extension protocols.  They can also be used
    to prevent the use of certain OpenID providers (or particular)
    identifiers for authentication.

    """

    def prepare_authn_request(req, auth_request):
        """ Possibly modify authn_request.

        This method is called before the authentication request is sent
        to the OP.  It might be used to add extension fields to the request.

        :type req: :class:`trac.web.api.Request`
        :type auth_request: :class:`openid.consumer.consumer.AuthRequest`

        """

    def parse_response(response, oid_identifier):
        """ Parse the response.

        This method is called after the reception of an affirmative response
        to an authentication request.

        This method might be used to extract information from
        extension fields in the response.  In this case the method
        probably will want to add any extracted information to the
        ``signed_data`` multidict on the ``oid_identifier`` object.
        Generally any data should be appended to that already in the
        ``signed_data`` dict (using :meth:``MultiDict.add``).  That
        way data provider by earlier extension providers will take
        precedence over that provided by later ones.

        .. NOTE:: Only data which comes from signed response fields should be
            placed into the ``signed_data`` dict.

        :type response: :class:`openid.consumer.consumer.SuccessResponse`
        :type oid_identifier: :class:`OpenIDIdentifier`

        """

    def is_trusted(response, oid_identifier):
        """ Determine whether the identifier is to be trusted for
        authentication

        This method is called after an affirmative response
        to an authentication request has been fully parsed.
        It can be used to prevent the use of the identifier for
        authentication.

        :type response: :class:`openid.consumer.consumer.SuccessResponse`
        :type oid_identifier: :class:`OpenIDIdentifier`

        :returns bool: Whether the identifier should be trusted.  If
            any of the request participants return ``False``,
            authentication will be considered to have failed.

        #FIXME: use a different exception type?
        :raises: :exc:`AuthenticationFailed`.  If the participant
            would like to provide feedback to the user as to why the
            identifier is not trusted, it can raise an
            :exc:`AuthenticationFailed` exception with an appropriate
            message.
        """

class IOpenIDRegistrationParticipant(Interface):
    """ Provides authorization as well as suggested username(s) and
    initial user data for new account registration via OpenID

    """
    # FIXME: maybe don't need the return value.  (Just raise exception.)?
    def authorize(req, oid_identifier):
        """ Determine whether user is authorized to register a new account.

        When a new user (one with an unrecognized OpenID identifier)
        attempts to log in, the :meth:`authorize` method of all
        enabled :class:`IOpenIDRegistrationParticipant`\s will be
        called to check whether the user should be allowed to create a
        new account on the trac.  If any of the participants raises
        :exc:`NotAuthorized`, or if none of the participants return a
        true value, authorization will be denied; otherwise if any of
        the participants returns a true value, new account registration
        will be permitted.

        :type req: :class:`trac.web.api.Request`
        :type identifier: :class:`IOpenIDIdentifier`

        :returns: ``True`` if the user is authorized to create a new
            account.  If the policy returns ``False``, it does not
            make any particular claims about the authorization of the
            user.

        :raises: :exc:`NotAuthorized` if the user is not authorized

        """

    def suggest_username(req, oid_identifier):
        """ Get suggested username for new account

        The :meth:`suggest_username` method will be called for all
        enabled :class:`IOpenIDRegistrationParticipant`\s.  The
        usernames return by all participants will be collected into a
        single sequence.  Usernames returned by earlier participants
        takes precedence over usernames from those listed later.

        :type req: :class:`trac.web.api.Request`
        :type identifier: :class:`IOpenIDIdentifier`

        :returns: A suggested username (trac SID) for the new account,
            or ``None`` if there is no suggestion.  Can also return a sequence
            of suggestions.
        """

    def get_user_data(req, oid_identifier):
        """ Get username and attributes for new account created via OpenID

        The :meth:`get_user_data` method will be called for all
        enabled :class:`IOpenIDRegistrationParticipant`\s.  The
        user data returned by all participants will merged.  Data
        returned by earlier participants takes precedence over that
        from those listed later.

        :type req: :class:`trac.web.api.Request`
        :type identifier: :class:`IOpenIDIdentifier`

        :returns: A dict of user attributes (probably containing keys
            ``'name'`` and ``'email'`` as well as perhaps others.)
        """

# FIXME: Rename to UnknownUser ?
class UserNotFound(KeyError):
    pass

class OpenIDIdentifierInUse(OpenIDException, KeyError):
    def __init__(self, username, identifier):
        msg = escape("User %s is already using identifier %s") % (
            tag.code(username), tag.code(identifier))
        super(OpenIDIdentifierInUse, self).__init__(msg, username, identifier)

    @property
    def username(self):
        return self.args[1]

    @property
    def identifier(self):
        return self.args[2]

class IOpenIDIdentifierStore(Interface):
    """ Manage the association between trac users and OpenID identifiers
    """
    def get_user(openid_identifier):
        """ Get trac username by OpenID identifier

        :returns: Trac username or ``None`` if no user found
        """

    def get_identifiers(username):
        """ Get OpenID identifiers for user
        """

    def add_identifier(username, openid_identifier):
        """ Add an OpenID identifier for the user

        :raises: :exc:`UserNotFound` if no user is found for ``username``
        :raises: :exc:`OpenIDIdentifierInUse` if another user is already
            associated with the ``openid_identifier``
        """

    def discard_identifier(username, openid_identifier):
        """ Remove an OpenID identifier for the user

        :raises: :exc:`UserNotFound` if no user is found for ``username``
        """

class IOpenIDUserRegistration(Interface):
    """ Creates new user accounts for OpenID authenticated users.

    Depending on configuration, this may or may not involve further
    user interaction.

    """
    def register_user(req, openid_identifier):
        """ Register a new OpenID-authenticated user.

        :raises: :exc:`RequestDone` This is a no-return method.
        """

class IOpenIDFancySelector(Interface):
    """ Support for pluggable fancy OpenID selectors.

    FIXME: Document
    """
    def populate_data(req, data):
        """ Mangle the template data
        """

class IOpenIDConsumer(Interface):
    """ Handle the nitty-gritty of OpenID authentication.

    Internal use.
    """
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
    """ Handle setting/clearing of the auth cookie to actually log the user in

    Internal use.
    """
    def login(req, username, referer=None):
        """ Log the user in as ``username`` and redirect to ``referer``

        The current session must be anonymous.
        """

    def logout(req, referer=None):
        """ Log the user out and redirect to ``referer``
        """
