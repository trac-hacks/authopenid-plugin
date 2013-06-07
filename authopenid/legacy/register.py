# -*- coding: utf-8 -*-
""" Legacy (authopenid version 0.4) configuration support for new
account registration
"""
from __future__ import absolute_import

from trac.core import implements, Component
from trac.config import BoolOption

from authopenid.api import (
    EMAIL_ADDRESS, FULL_NAME, NICKNAME,
    IOpenIDRegistrationParticipant,
    )

class LegacyUsername(Component):
    """ Implements the legacy (authopenid version 0.4) logic for
    picking new user usernames.

    """
    implements(IOpenIDRegistrationParticipant)

    use_nickname_as_authname = BoolOption(
        'openid', 'use_nickname_as_authname', False,
        """ Whether the nickname as retrieved by SReg is used as
        username""")

    combined_username = BoolOption(
        'openid', 'combined_username', False,
        """ Username will be written as username_in_remote_system
        <openid_url>.""")

    strip_protocol = BoolOption(
        'openid', 'strip_protocol', False,
        """Instead of using username beginning with http:// or
        https:// you can strip the beginning.""")

    strip_trailing_slash = BoolOption(
        'openid', 'strip_trailing_slash', False,
        """In case your OpenID is some sub-domain address OpenId
        library adds trailing slash. This option strips it.""")


    def authorize(self, req, oid_identifier):
        return True                     # FIXME: ?

    def suggest_username(self, req, oid_identifier):
        signed_data = oid_identifier.signed_data
        if self.use_nickname_as_authname:
            return signed_data.get(NICKNAME)
        elif signed_data.get(FULL_NAME):
            username = signed_data.get(FULL_NAME)
            if self.combined_username:
                username += ' <%s>' % self._cleanup_identifier(oid_identifier)
            return username
        else:
            return self._cleanup_identifier(oid_identifier)

    # FIXME: put this in it's own component (DefaultUserData or some such)
    def get_user_data(self, req, oid_identifier):
        signed_data = oid_identifier.signed_data
        data = {}
        for akey, dkey in [('name', FULL_NAME), ('email', EMAIL_ADDRESS)]:
            for value in (v.strip() for v in signed_data.getall(dkey)):
                if value:
                    data[akey] = value
                    break
        return data

    def _cleanup_identifier(self, oid_identifier):
        ident = oid_identifier
        if self.strip_protocol:
            ident = ident.split('://', 1)[-1]
        if self.strip_trailing_slash and ident.endswith('/'):
            ident = ident[:-1]
        return ident
