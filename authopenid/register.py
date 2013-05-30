# -*- coding: utf-8 -*-
"""
"""
from __future__ import absolute_import

import re

from genshi.builder import tag
from trac.core import implements
from trac.config import BoolOption
from trac.web import chrome
from trac.web.session import DetachedSession

from authopenid.api import (
    FULL_NAME, EMAIL_ADDRESS, NICKNAME,
    IOpenIDUserRegistration,
    )
from authopenid.authopenid import AuthOpenIdPlugin
from authopenid.compat import Component

# FIXME: support interactive username selection
#   - also (optionally) allow user to adjust email, fullname?

class OpenIDLegacyRegistrationModule(Component):
    """ Handles new user registration for OpenID-authenticated users.

    This does this more-or-less in the style of version 0.4 of
    the ``TracAuthOpenId`` plugin, without any further user interaction.

    """
    implements(IOpenIDUserRegistration)


    combined_username = BoolOption(
        'openid', 'combined_username', False,
        """ Username will be written as username_in_remote_system
        <openid_url>.""")

    use_nickname_as_authname = BoolOption(
        'openid', 'use_nickname_as_authname', False,
        """ Whether the nickname as retrieved by SReg is used as
        username""")

    trust_authname = BoolOption(
        'openid', 'trust_authname', False,
        """WARNING: Only enable this if you know what this mean!  This
        could make identity theft very easy if you do not control the
        OpenID provider!  Enabling this option makes the retrieved
        authname from the OpenID provider authorative, i.e. it trusts
        the authname to be the unique username of the user. Enabling
        this disables the collission checking, so two different OpenID
        urls may suddenly get the same username if they have the same
        authname""")


    def __init__(self):
        authopenid = AuthOpenIdPlugin(self.env)
        # FIXME: should probably do these later
        self.identifier_store = authopenid.identifier_store
        self.user_login = authopenid.user_login

    # FIXME: should add config to disable new account creation
    # FIXME: trust_authname
    # FIXME: combined_username?

    # FIXME: more controls for how to uniquify the username?
    # Maybe not necessary once the interactive username selection is
    # working.

    # FIXME: handle username case

    # FIXME: check for illegal usernames.
    #  (This list gleaned from the TracAccountManager plugin.)
    #   - No ':', '[', ']'
    #   - No all upper case (those are permissions)
    #   - username.lower() not in ('anonymous', 'authenticated')
    #   - do a case-insenstive check against existing usernames
    #     - also consider any static lists of potential usernames
    def register_user(self, req, openid_identifier):
        """ Register a new OpenID-authenticated user.

        This does this more-or-less in the style of version 0.4 of
        the ``TracAuthOpenId`` plugin, without any further user interaction.

        This is a no-return method: a normal exit is via :exc:`RequestDone`.
        """

        identifier_store = AuthOpenIdPlugin(self.env).identifier_store

        username = None
        for username in self._valid_usernames(req, openid_identifier):
            with self.env.db_transaction as db:
                user = DetachedSession(self.env, username)
                if not user._new:
                    continue            # user exists

                user.update(self._get_user_attributes(openid_identifier))
                if len(user) > 0:
                    user.save()
                else:
                    # user.save won't create a new user with no data
                    db("INSERT INTO session"
                       " (sid, authenticated, last_visit)"
                       " VALUES (%s, 1, 0)", (username,))

                self.identifier_store.add_identifier(username,
                                                     openid_identifier)
                break
        else:
            # FIXME: cleanup
            if username:
                msg = "A user already exists with username %r" % username
            else:
                msg = "Could not deduce a valid username"
            chrome.add_warning(req, tag("Can not complete registration. ", msg))
            req.redirect(req.href.openid('login'))

        chrome.add_warning(req, tag(
            "Successfully completed OpenID user registration. "
            "Your new username is ", tag.code(username), "."
            ))
        referer = None                  # FIXME:
        self.user_login.login(req, username, referer)

    def _validate_username(self, req, username):
        # FIXME: ':' not being a valid character means identifier URLs
        # are not allowed?
        #
        #  (This list gleaned from the TracAccountManager plugin.)
        #   - No ':', '[', ']'
        #   - No all upper case (those are permissions)
        #   - username.lower() not in ('anonymous', 'authenticated')
        #   - do a case-insenstive check against existing usernames
        #     - also consider any static lists of potential usernames
        # FIXME: make this more lenient/configurable (is unicode allowed?)
        return (
            re.match(r'\A(?!\s)[-=\w\d@\. ()]+(?!<\s)\Z', username)
            and not username.isupper()
            and username.lower() not in ('anonymous', 'authenticated')
            )

    def _valid_usernames(self, req, openid_identifier):
        seen = set()
        for username in self._possible_usernames(openid_identifier):
            username = self._maybe_lowercase_username(username)
            if username in seen:
                continue
            seen.add(username)
            if not self._validate_username(req, username):
                # FIXME: better message(s))
                chrome.add_warning(req, "%r is not a valid username" % username)
                continue
            yield username

    def _possible_usernames(self, openid_identifier):
        preferred = tuple(self._preferred_usernames(openid_identifier))
        for username in preferred:
            yield username
        for n in range(2, 1000):
            for username in preferred:
                yield "%s (%d)" % (username, n)

    def _preferred_usernames(self, openid_identifier):
        # FIXME: configuration

        seen = set()
        for key in FULL_NAME, NICKNAME, EMAIL_ADDRESS:
            for value in openid_identifier.signed_data.getall(key):
                value = value.strip()
                if value and value not in seen:
                    seen.add(value)
                    yield value
        if len(seen) == 0:
            # punt
            yield str(openid_identifier)

    # FIXME: unify with the same method in OpenIDIdentifierStore
    def _maybe_lowercase_username(self, username):
        if self.config.getbool('trac', 'ignore_auth_case'):
            return username.lower()
        return username

    def _get_user_attributes(self, openid_identifier):
        signed_data = openid_identifier.signed_data
        for akey, dkey in [('name', FULL_NAME), ('email', EMAIL_ADDRESS)]:
            try:
                value = next(v.strip() for v in signed_data.getall(dkey)
                             if v.strip())
            except StopIteration:
                continue
            yield akey, value
