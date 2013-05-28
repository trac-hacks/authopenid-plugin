from __future__ import absolute_import

import re

from trac.core import Component, implements
from trac.config import ListOption

from authopenid.api import (
    EMAIL_ADDRESS,
    IOpenIDAuthorizationPolicy,
    NotAuthorized,
    )

class WhitelistAuthorizer(Component):
    """ Implements whitelist/blacklist authorization.

    XXX: Maybe move the email checking into a separate component.
    """
    implements(IOpenIDAuthorizationPolicy)

    white_list = ListOption('openid', 'white_list',
        doc="""Comma separated list of allowed OpenId identifiers.

        If set, only OpenID identifiers that match one of these patterns
        will be allowed to log in.
        """)

    black_list = ListOption('openid', 'black_list',
        doc="""Comma separated list of denied OpenId identifiers.

        If set, any OpenID identifiers that match one of these patterns
        will not be allowed to log in.
        """)

    email_white_list = ListOption('openid', 'email_white_list',
        doc="""Comma separated list of allowed user email addresses.

        If set, only users whose email address (as determined via SREG
        or AX) matches a pattern in this list will be allowed to log
        in.

        This probably should be used in combination with trusted
        identity patterns in white_list.
        """)

    def __init__(self):
        self.white_list_re = _compile_patterns(self.white_list)
        self.black_list_re = _compile_patterns(self.black_list)
        self.email_white_list_re = _compile_patterns(self.email_white_list)

    def authorize(self, identifier):
        log = self.log

        # FIXME: the logic here is wierd, (but, I think, matches the
        # previous version of the plugin.)

        if self.white_list_re:
            log.debug("checking white_list")
            if not self.white_list_re.match(identifier):
                log.info("white_list does not match identity %r", identifier)
                raise NotAuthorized()

        if self.black_list_re:
            log.debug("checking black_list")
            if self.black_list_re.match(identifier):
                log.info("black_list blocks identity %r", identifier)
                raise NotAuthorized()

        if self.email_white_list_re:
            try:
                email = identifier.signed_data[EMAIL_ADDRESS]
            except KeyError:
                log.info("No email address returned by OP")
                raise NotAuthorized()
            log.debug("checking email_white_list")
            if not self.email_white_list_re.match(email):
                log.info("email_white_list does not match %r", email)
                raise NotAuthorized()

        # FIXME: Really should return False if not white lists are
        # configured.  For now we always return true since that matches
        # previous behavior.
        return True

def _compile_patterns(patterns):
    """ Compile sequence of patterns to a regular expression.

    Returns a compiled regular expression which will match any of the
    patterns, or ``None`` if patterns is empty.
    """
    if not patterns:
        return None
    regexps = [ '.*'.join(re.escape(part) for part in pattern.split('*'))
                for pattern in patterns ]
    return re.compile(r'\A(?:%s)\Z' % '|'.join(regexps))
