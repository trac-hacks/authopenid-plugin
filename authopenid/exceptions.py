from genshi.core import Markup

class UserExists(KeyError):
    """ Raised by ``UserManager`` when creating a user if username is
    not distinct.

    """

class UserLookupError(KeyError):
    """ General failure during user lookup.
    """

class IdentifierNotUnique(UserLookupError):
    """ Multiple users share the same OpenID identifier
    """

# FIXME: use trac.core.TracError instead?
class _MarkupExceptionBase(Exception):
    """ Base case for exceptions which can be safely formatted as HTML.
    """
    def __html__(self):
        """ Get HTML representation.

        This allows for HTML error messages::

            from genshi.build import tag
            raise OpenIDException('I am not ', tag.code('square'))
        """
        message = self.args[0] if self.args else self.__class__.__name__
        return Markup.escape(message)

    def __unicode__(self):
        return self.__html__().striptags().stripentities()

    def __str__(self):
        return self.__unicode__().encode('utf-8')

class LoginException(_MarkupExceptionBase):
    """ Exceptions raised during login which should be shown to the user.

    This is a base class for authentication exceptions which should be
    displayed to the user (somehow).
    """

class LoginError(LoginException):
    """ Login error.

    These should be displayed to the user, with color/highlighting as
    appropriate for errors.
    """

class LoginWarning(LoginException):
    """ Login warning.

    These should be displayed to the user, with color/highlighting as
    appropriate for warnings.
    """

class NotAuthorized(LoginError):
    """ Authorization failure.

    This is raised when the user has successfully authenticated (via OpenID)
    but the user is not authorized to log in to the site.
    """
    def __init__(self):
        super(NotAuthorized, self).__init__("Not authorized")
