# -*- coding: utf-8 -*-
"""
"""
from __future__ import absolute_import

from itertools import count
from pkg_resources import resource_filename
import re

from genshi.core import escape
from genshi.builder import tag
from trac.core import implements
from trac.config import BoolOption, OrderedExtensionsOption
from trac.perm import PermissionSystem
from trac.web import chrome
from trac.web.chrome import ITemplateProvider
from trac.web.main import IRequestHandler
from trac.web.session import DetachedSession

from authopenid.api import (
    OpenIDException,
    NotAuthorized,
    FULL_NAME, EMAIL_ADDRESS, NICKNAME,
    IOpenIDRegistrationParticipant,
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


class OpenIDInteractiveRegistrationModule(Component):
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
        helper = RegistrationHelper(self.env)

        try:
            helper.check_authorization(req, openid_identifier)
        except NotAuthorized as exc:
            chrome.add_warning(req, exc)
            req.redirect(req.href.openid('login'))

        oid_session = AuthOpenIdPlugin(self.env).get_session(req)
        oid_session['register.identifier'] = openid_identifier

        for username in helper.suggested_usernames(req, openid_identifier):
            username = helper.maybe_lowercase_username(username)
            if helper.is_valid_username(username):
                break
        else:
            username = ''
        user_attr = helper.user_attributes(req, openid_identifier)

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

        username = req.args.getfirst('username', '')

        oid_session = AuthOpenIdPlugin(self.env).get_session(req)
        oid_identifier = oid_session.get('register.identifier')
        if not oid_identifier:
            # shouldn't happen unless the user is doing something funny
            # like re-posting the register form
            self.log.warning(
                "No openid identifier in session for registration")
            req.redirect(req.href())

        helper = RegistrationHelper(self.env)
        username = helper.maybe_lowercase_username(username)
        user_attr = helper.user_attributes(req, oid_identifier)

        try:
            helper.create_user(username, oid_identifier, user_attr)
        except InvalidUsername as exc:
            chrome.add_warning(req, exc)
            return self._register_form(req, username, user_attr)

        chrome.add_notice(req, escape(
            "Successfully completed new OpenID user registration. "
            "Your new username is %s.") % tag.code(username))
        del oid_session['register.identifier']

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


class OpenIDLegacyRegistrationModule(Component):
    """ Handles new user registration for OpenID-authenticated users.

    This does this more-or-less in the style of version 0.4 of
    the ``TracAuthOpenId`` plugin, without any further user interaction.

    """
    implements(IOpenIDUserRegistration)


    # FIXME: trust_authname: use this!
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


    # FIXME: should coument config to disable new account creation
    #  (just disable all Registration Participants)

    def register_user(self, req, openid_identifier):
        """ Register a new OpenID-authenticated user.

        This does this more-or-less in the style of version 0.4 of
        the ``TracAuthOpenId`` plugin, without any further user interaction.

        This is a no-return method: a normal exit is via :exc:`RequestDone`.
        """

        identifier_store = AuthOpenIdPlugin(self.env).identifier_store
        user_login = AuthOpenIdPlugin(self.env).user_login
        helper = RegistrationHelper(self.env)

        try:
            helper.check_authorization(req, openid_identifier)
        except NotAuthorized as exc:
            chrome.add_warning(req, exc)
            req.redirect(req.href.openid('login'))

        user_attr = helper.user_attributes(req, openid_identifier)
        candidates = []
        for username in helper.suggested_usernames(req, openid_identifier,
                                                   fallback_to_identifier=True):
            username = helper.maybe_lowercase_username(username)
            try:
                helper.create_user(username, openid_identifier, user_attr)
                break
            except UserExists:
                candidates.append(username)
                continue
            except InvalidUsername as exc:
                self.log.warning("%r is not a valid username", username)
        else:
            for username in self._uniquify_usernames(candidates):
                try:
                    helper.create_user(username, openid_identifier, user_attr)
                    break
                except UserExists:
                    continue
            else:
                chrome.add_warning(req, "Can not complete registration:"
                                   " could not deduce a valid username")
                req.redirect(req.href.openid('login'))

        chrome.add_notice(req, escape(
            "Successfully completed OpenID user registration. "
            "Your new username is %s.") % tag.code(username))
        start_page = AuthOpenIdPlugin(self.env).get_start_page(req)
        user_login.login(req, username, start_page)

    def _uniquify_usernames(self, candidates):
        for n in count(2):
            for u in candidates:
                yield "%s (%d)" % (u, n)

class DefaultRegistrationParticipant(Component):
    implements(IOpenIDRegistrationParticipant)

    # FIXME: combined_username?
    combined_username = BoolOption(
        'openid', 'combined_username', False,
        """ Username will be written as username_in_remote_system
        <openid_url>.""")

    # FIXME: use_nickname_as_authname: use or refactor this
    use_nickname_as_authname = BoolOption(
        'openid', 'use_nickname_as_authname', False,
        """ Whether the nickname as retrieved by SReg is used as
        username""")


    def authorize(self, req, oid_identifier):
        return True                     # FIXME: ?

    def suggest_username(self, req, oid_identifier):
        # FIXME: make configurable
        seen = set()
        for key in FULL_NAME, NICKNAME, EMAIL_ADDRESS:
            for value in oid_identifier.signed_data.getall(key):
                if value and value not in seen:
                    seen.add(value)
                    yield value

    def get_user_data(self, req, oid_identifier):
        signed_data = oid_identifier.signed_data
        data = {}
        for akey, dkey in [('name', FULL_NAME), ('email', EMAIL_ADDRESS)]:
            for value in (v.strip() for v in signed_data.getall(dkey)):
                if value:
                    data[akey] = value
                    break
        return data

class RegistrationHelper(Component):
    required = True

    registration_participants = OrderedExtensionsOption(
        'openid', 'registration_participants', IOpenIDRegistrationParticipant)

    # FIXME:rename
    def check_authorization(self, req, identifier):
        """
        :raises: :exc:`NotAuthorized`
        """
        results = [ participant.authorize(req, identifier)
                    for participant in self.registration_participants ]
        if len(results) == 0:
            raise NotAuthorized(
                "New account registration via OpenID is not enabled")
        elif not any(bool(result) is True for result in results):
            raise NotAuthorized(
                escape("OpenID identifier %s is not authorized to create"
                       " an account here") % tag.code(identifier))

    def suggested_usernames(self, req, identifier,
                            fallback_to_identifier=False):
        seen = set()
        for participant in self.registration_participants:
            suggestions = participant.suggest_username(req, identifier)
            if suggestions is not None:
                if not hasattr(suggestions, '__iter__') \
                       or isinstance(suggestions, basestring):
                    suggestions = [suggestions]
                for suggestion in suggestions:
                    username = self.maybe_lowercase_username(suggestion)
                    if username not in seen:
                        seen.add(username)
                        yield suggestion
        if len(seen) == 0 and fallback_to_identifier:
            yield identifier

    def user_attributes(self, req, identifier):
        user_data = {}
        for participant in self.registration_participants:
            d = participant.get_user_data(req, identifier)
            if d:
                d.update(user_data)
                user_data = d
        return user_data

    def check_username(self, username):
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

        # Check against all usernames in the permission system.  (Some of
        # these 'usernames' can be group names.  If we allowed creating a
        # new user with the name of a group, he/she would get all the group
        # permissions (I'm pretty sure...))
        #
        # FIXME: (optionally?) do this existing user check in a
        # case-insensitive manner?
        all_permissions = PermissionSystem(self.env).get_all_permissions()
        existing_users_and_groups = set(user for user, perm in all_permissions)
        if username in existing_users_and_groups:
            raise UserExists(username, "in use by another user")


    def is_valid_username(self, username):
        try:
            self.check_username(username)
        except InvalidUsername:
            return False
        return True

    # FIXME: unify with the same method in OpenIDIdentifierStore
    def maybe_lowercase_username(self, username):
        if self.config.getbool('trac', 'ignore_auth_case'):
            return username.lower()
        return username

    def create_user(self, username, openid_identifier=None,  user_attr=None):
        identifier_store = AuthOpenIdPlugin(self.env).identifier_store

        if self.maybe_lowercase_username(username) != username:
            raise ValueError("username must be lowercase since"
                             " [trac]ignore_auth_case is set")
        self.check_username(username)
        with self.env.db_transaction as db:
            user = DetachedSession(self.env, username)
            if not user._new:
                raise UserExists(username, "in use by another user")

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
