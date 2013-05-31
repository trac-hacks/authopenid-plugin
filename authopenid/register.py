# -*- coding: utf-8 -*-
"""
"""
from __future__ import absolute_import

from pkg_resources import resource_filename
import re

from genshi.core import escape
from genshi.builder import tag
from trac.core import implements
from trac.config import BoolOption
from trac.web import chrome
from trac.web.chrome import ITemplateProvider
from trac.web.main import IRequestHandler
from trac.web.session import DetachedSession

from authopenid.api import (
    OpenIDException,
    FULL_NAME, EMAIL_ADDRESS, NICKNAME,
    IOpenIDUserRegistration,
    )
from authopenid.authopenid import AuthOpenIdPlugin
from authopenid.compat import Component

# FIXME: probably move exceptions to api
class InvalidUsername(OpenIDException, ValueError):
    def __init__(self, username, detail=None):
        msg = escape("%s is not a valid username") % tag.code(username)
        if detail:
            msg += escape(": %s") % detail
        super(InvalidUsername, self).__init__(msg, username, detail)

    @property
    def username(self):
        return self.args[1]

    @property
    def detail(self):
        return self.args[2]

class UserExists(InvalidUsername):
    pass


class RegistrationModuleBase(Component):
    abstract = True

    def _check_username(self, username):
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
        if not username:
            raise InvalidUsername(username, "empty username")
        if username.strip() != username:
            raise InvalidUsername(username, "leading or trailing white space")
        if username.isupper():
            raise InvalidUsername(username, "can not be all upper case")
        if username.lower() in ('anonymous', 'authenticated'):
            raise InvalidUsername(username, "reserved")
        if not re.match(r'\A(?!\s)[-=\w\d@\. ()]+(?!<\s)\Z', username):
            raise InvalidUsername(username, "invalid characters in username")

    def _is_valid_username(self, username):
        try:
            self._check_username(username)
        except InvalidUsername:
            return False
        return True

    def _validate_username(self, req, username):
        username = self._maybe_lowercase_username(
            username.strip() if username else '')
        try:
            self._check_username(username)
        except InvalidUsername as exc:
            chrome.add_warning(req, exc)
            raise
        return username

    def _get_user_attributes(self, openid_identifier):
        # FIXME: this should be done by some other component(s) (so as
        # to be configurable.)  Might want data from SREG/AX, might want
        # to do external file or http lookup, etc, etc...
        signed_data = openid_identifier.signed_data
        for akey, dkey in [('name', FULL_NAME), ('email', EMAIL_ADDRESS)]:
            try:
                value = next(v.strip() for v in signed_data.getall(dkey)
                             if v.strip())
            except StopIteration:
                continue
            yield akey, value

    def _preferred_usernames(self, openid_identifier):
        # FIXME: this should be done by some other component(s) (so as
        # to be configurable.)  Might want data from SREG/AX, might want
        # to do external file or http lookup, etc, etc...
        seen = set()
        for key in FULL_NAME, NICKNAME, EMAIL_ADDRESS:
            for value in openid_identifier.signed_data.getall(key):
                value = self._maybe_lowercase_username(value.strip())
                if value and value not in seen:
                    seen.add(value)
                    yield value

    # FIXME: unify with the same method in OpenIDIdentifierStore
    def _maybe_lowercase_username(self, username):
        if self.config.getbool('trac', 'ignore_auth_case'):
            return username.lower()
        return username

    # Move this somewhere else (it might be more generally useful)?
    def _create_user(self, username, openid_identifier=None,  user_attr=None):
        # FIXME: check for conflicts with existing usernames differing
        # only in case?
        identifier_store = AuthOpenIdPlugin(self.env).identifier_store

        with self.env.db_transaction as db:
            user = DetachedSession(self.env, username)
            if not user._new:
                raise UserExists(username, "is use by another user")

            if user_attr:
                user.update(user_attr)
            if len(user) > 0:
                user.save()
            else:
                # user.save won't create a new user with no data
                db("INSERT INTO session"
                   " (sid, authenticated, last_visit)"
                   " VALUES (%s, 1, 0)", (username,))

            if openid_identifier:
                identifier_store.add_identifier(username, openid_identifier)


class OpenIDInteractiveRegistrationModule(RegistrationModuleBase):
    """ Handles new user registration for OpenID-authenticated users.

    This is a new interactive version which lets the user choose
    the username for the new trac account.

    """
    implements(ITemplateProvider, IRequestHandler,
               IOpenIDUserRegistration)

    # FIXME: allow user to edit name, email?  (needs config, probably)

    # IOpenIDUserRegistration
    def register_user(self, req, openid_identifier):
        """ Register a new OpenID-authenticated user.

        This displays a registration form which allows the user to
        select the username for his/her new trac account.

        This is a no-return method: a normal exit is via :exc:`RequestDone`.
        """
        oid_session = AuthOpenIdPlugin(self.env).get_session(req)
        oid_session['register.identifier'] = openid_identifier

        candidates = filter(self._is_valid_username,
                            self._preferred_usernames(openid_identifier))
        username = candidates[0] if candidates else ''
        user_attr = dict(self._get_user_attributes(openid_identifier))

        return self._register_form(req, username, user_attr)

    # ITemplateProvider methods
    def get_htdocs_dirs(self):
        return [('authopenid', resource_filename(__name__, 'htdocs'))]

    def get_templates_dirs(self):
        return [resource_filename(__name__, 'templates')]

    # IRequestHandler methods
    def match_request(self, req):
        return req.path_info == '/openid/register'

    def process_request(self, req):
        if req.authname != 'anonymous':
            chrome.add_warning(req, "Already logged in!")
            return req.redirect(AuthOpenIdPlugin(self.env).get_start_page(req))

        oid_session = AuthOpenIdPlugin(self.env).get_session(req)
        oid_identifier = oid_session.get('register.identifier')
        if not oid_identifier:
            # shouldn't happen unless the user is doing something funny
            # like re-posting the register form
            self.log.warning(
                "No openid identifier in session for registration")
            req.redirect(req.href())
        user_attr = dict(self._get_user_attributes(oid_identifier))

        try:
            username = self._validate_username(
                req, req.args.getfirst('username', ''))
        except InvalidUsername:
            # _validate_username has already added chrome warning
            return self._register_form(req, username, user_attr)

        try:
            self._create_user(username, oid_identifier, user_attr)
        except UserExists as exc:
            chrome.add_warning(exc)
            return self._register_form(req, username, user_attr)

        chrome.add_notice(req, escape(
            "Successfully completed new OpenID user registration. "
            "Your new username is %s.") % tag.code(username))

        authopenid = AuthOpenIdPlugin(self.env)
        start_page = authopenid.get_start_page(req)
        authopenid.user_login.login(req, username, start_page)

    def _register_form(self, req, username, user_attr):
        data = {
            'username': username,
            'register_url': req.href.openid('register'),
            'name': user_attr.get('name', ''),
            'email': user_attr.get('email', ''),
            }
        return 'openid_register.html', data, None


class OpenIDLegacyRegistrationModule(RegistrationModuleBase):
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
        user_login = AuthOpenIdPlugin(self.env).user_login

        candidates = list(self._preferred_usernames(openid_identifier))
        if not candidates:
            candidates = [str(openid_identifier)]
        for username in list(candidates):
            if not self._is_valid_username(username + ' (1)'):
                self.log.warning("%r is not a valid username", username)
                candidates.remove(username)

        user_attr = dict(self._get_user_attributes(openid_identifier))

        for username in self._possible_usernames(candidates):
            try:
                self._create_user(username, openid_identifier, user_attr)
                break
            except UserExists:
                continue
        else:
            if username:
                msg = escape("A user already exists with username %r"
                             ) % tag.code(username)
            else:
                msg = "Could not deduce a valid username"
            chrome.add_warning(req, escape("Can not complete registration: %s"
                                           ) % msg)
            req.redirect(req.href.openid('login'))

        chrome.add_notice(req, escape(
            "Successfully completed OpenID user registration. "
            "Your new username is %s.") % tag.code(username))
        start_page = AuthOpenIdPlugin(self.env).get_start_page(req)
        user_login.login(req, username, start_page)

    def _possible_usernames(self, candidates):
        for username in candidates:
            if self._is_valid_username(username):
                yield username
        for n in range(2, 1000):
            for u in candidates:
                username = "%s (%d)" % (u, n)
                assert self._is_valid_username(username)
                yield username
