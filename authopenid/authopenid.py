# -*- coding: utf-8 -*-
#
# Copyright (C) 2007-2013 Dalius Dobravolskas and Geoffrey T. Dairiki
# All rights reserved.
#
# This software is licensed using the same licence as Trac:
# http://trac.edgewall.org/wiki/TracLicense.
#
# Original Author: Dalius Dobravolskas <dalius@sandbox.lt>
# Current Maintainer: Jeff Dairiki <dairiki@dairiki.org>

from __future__ import absolute_import

from pkg_resources import resource_filename

from trac.core import Component, implements, TracError
from trac.config import (
    BoolOption,
    ChoiceOption,
    ConfigurationError,
    ExtensionOption,
    ListOption,
    Option,
    OrderedExtensionsOption,
    )
from trac.web import chrome
from trac.web.chrome import INavigationContributor, ITemplateProvider
from trac.web.main import IRequestHandler
from trac.web.auth import LoginModule

from genshi.builder import tag
from genshi.core import Markup

from authopenid.api import (
    DiscoveryFailure,
    NegativeAssertion,
    NotAuthorized,
    IOpenIDAuthorizationPolicy,
    IOpenIDIdentifierStore,
    IOpenIDUserRegistration,
    )
from authopenid.interfaces import (
    IOpenIDConsumer,
    IUserLogin,
    )
from authopenid.util import sanitize_referer

## Options we used to support but no longer do
_DISCONTINUED_OPTIONS = [
    ('trac', 'check_auth_ip_mask'),
    ('trac', 'expires'),
    ('openid', 'lowercase_authname'),
    ('openid', 'timeout'),
    ]

## List of components which might provide a 'Logout' navagation link
_LOGIN_MODULES = [LoginModule]
try:
    from acct_mgr.web_ui import LoginModule as acct_mgr_LoginModule
    _LOGIN_MODULES.append(acct_mgr_LoginModule)
except ImportError:
    pass


class AuthOpenIdPlugin(Component):
    implements(INavigationContributor, ITemplateProvider, IRequestHandler)

    ################################################################
    # Configuration

    default_openid = Option('openid', 'default_openid', None,
            """Default OpenID provider for directed identity.""")

    strip_protocol = BoolOption('openid', 'strip_protocol', False,
            """Instead of using username beginning with http:// or https:// you can strip the beginning.""")

    strip_trailing_slash = BoolOption('openid', 'strip_trailing_slash', False,
            """In case your OpenID is some sub-domain address OpenId library adds trailing slash. This option strips it.""")

    signup_link = Option('openid', 'signup', 'http://openid.net/get/',
            """Signup link""")

    whatis_link = Option('openid', 'whatis', 'http://openid.net/what/',
            """What is OpenId link.""")


    check_list = Option('openid', 'check_list', None,
            """JSON service for openid check.""")

    check_list_key = Option('openid', 'check_list_key', 'check_list',
            """Key for openid Service.""")

    check_list_username = Option('openid', 'check_list_username', None,
            """Username for openid Service.""")

    providers = ListOption('openid', 'providers', [],
        doc="""Explicit set of providers to offer.

        E.g: google, yahoo, ...""")

    custom_provider_name = Option('openid', 'custom_provider_name', None,
            """ Custom OpenId provider name. """)

    custom_provider_label = Option('openid', 'custom_provider_label', 'Enter your username',
            """ Custom OpenId provider label. """)

    custom_provider_url = Option('openid', 'custom_provider_url', '',
            """ Custom OpenId provider URL. E.g.: http://claimid.com/{username} """)

    custom_provider_image = Option('openid', 'custom_provider_image', '',
            """ Custom OpenId provider image. """)

    custom_provider_size = ChoiceOption('openid', 'custom_provider_size',
                                        ('small', 'large'),
        doc=""" Custom OpenId provider image size (small or large).""")


    authorization_policies = OrderedExtensionsOption(
        'openid', 'authorization_policies', IOpenIDAuthorizationPolicy)

    identifier_store = ExtensionOption(
        'openid', 'identifier_store', IOpenIDIdentifierStore,
        default='OpenIDIdentifierStore')

    registration_module = ExtensionOption(
        'openid', 'registration_module', IOpenIDUserRegistration,
        default='OpenIDLegacyRegistrationModule')

    user_login = ExtensionOption(
        'openid', 'user_login_provider', IUserLogin, default='UserLogin')

    openid_consumer = ExtensionOption(
        'openid', 'openid_consumer', IOpenIDConsumer,
        default='OpenIDConsumer')

    def __init__(self):
        config = self.config

        for section, entry in _DISCONTINUED_OPTIONS:
            if config.get(section, entry):
                raise ConfigurationError(
                    '[%(section)s] %(entry)s: option no longer supported'
                    % dict(section=section, entry=entry))

        self.template_data = {
            'signup': self.signup_link,
            'whatis': self.whatis_link,
            'providers_regexp': '^(%s)$' % '|'.join(self.providers or ['.*']),
            'custom_provider_name': self.custom_provider_name,
            'custom_provider_label': self.custom_provider_label,
            'custom_provider_url': self.custom_provider_url,
            'custom_provider_image': self.custom_provider_image,
            'custom_provider_size': self.custom_provider_size,
            }

        if len(self.authorization_policies) == 0:
            raise TracError("No OpenID authorization_policies are configured")

    # INavigationContributor methods
    def get_active_navigation_item(self, req):
        return 'openid/login'

    def get_navigation_items(self, req):
        if not req.authname or req.authname == 'anonymous':
            self_url = req.href(req.path_info)
            login_url = req.href.openid('login', referer=self_url)
            yield ('metanav', 'openid/login',
                   tag.a('OpenID Login', href=login_url))
        elif not any(self.env.is_component_enabled(comp)
                     for comp in _LOGIN_MODULES):
            # FIXME: Add config to show name rather than sid (b/c)
            yield ('metanav', 'openid/login', 'logged in as %s' % req.authname)

            yield ('metanav', 'openid/logout',
                   tag.a('Logout', href=req.href.openid('logout')))

    # ITemplateProvider methods
    def get_htdocs_dirs(self):
        return [('authopenid', resource_filename(__name__, 'htdocs'))]

    def get_templates_dirs(self):
        return [resource_filename(__name__, 'templates')]

    # IRequestHandler methods
    def match_request(self, req):
        return req.path_info in (
            '/openid/login', '/openid/logout', '/openid/response')

    def process_request(self, req):
        # FIXME: move this to LoginModule?
        if req.path_info == '/openid/logout':
            return self._do_logout(req)

        if req.authname != 'anonymous':
            chrome.add_warning(req, "Already logged in")
            return req.redirect(self._get_referer(req))

        if req.path_info == '/openid/login':
            return self._do_login(req)
        elif req.path_info == '/openid/response':
            return self._do_process(req)

    def _do_login(self, req):

        assert req.authname == 'anonymous'

        if req.args.get('referer'):
            self._save_referer(req)

        if req.method == 'POST':
            openid_identifier = req.args.get('openid_identifier')
            immediate = 'immediate' in req.args # FIXME: used?
        elif self.default_openid:
            openid_identifier = self.default_openid
            immediate = False
        else:
            return self._login_form(req)

        if not openid_identifier:
            chrome.add_warning(req, "Enter an OpenID Identifier")
            return self._login_form(req)

        return_to = req.abs_href.openid('response')

        try:
            return self.openid_consumer.begin(
                req, openid_identifier, return_to, immediate=immediate)
        except DiscoveryFailure as exc:
            chrome.add_warning(req, Markup(exc))
            return self._login_form(req)


    def _do_process(self, req):
        """Handle the redirect from the OpenID server.
        """
        assert req.authname == 'anonymous'

        try:
            identifier = self.openid_consumer.complete(req)
        except NegativeAssertion as exc:
            chrome.add_warning(req, Markup(exc))
            return self._login_form(req)

        # FIXME: should authz checks be performed only for new accounts?
        try:
            self._check_authorization(identifier)
        except NotAuthorized as exc:
            chrome.add_warning(req, Markup(exc))
            return self._login_form(req)

        # This could be abstracted?
        #username = self.get_username(identity, extension_data)
        #if not username:
        #    # FIXME:
        #    raise FIXME("No user found for identity")

        #referer = self._get_referer(req)
        #return self.user_login.login(req, username, referer)

        username = self.identifier_store.get_user(identifier)
        # XXX: update name/email if account already exists?

        if username is None:
            return self.registration_module.register_user(req, identifier)

        # Complete the user logLog the user in
        referer = self._get_referer(req)
        self.user_login.login(req, username, referer)


    def _do_logout(self, req):
        """Log the user out.
        """
        self.user_login.logout(req)

    def _check_authorization(self, identifier):
        # make sure to call all authorization providers to give each
        # a chance to raise NotAuthorized
        results = [ policy.authorize(identifier)
                    for policy in self.authorization_policies ]
        if not any(bool(result) is True for result in results):
            # FIXME: better message
            raise NotAuthorized(
                    "No configured authorization policy matched")

    def _login_form(self, req):
        img_path = req.href.chrome('authopenid/images') + '/'

        chrome.add_stylesheet(req, 'authopenid/css/openid.css')
        chrome.add_script(req, 'authopenid/js/openid-jquery.js')
        data = dict(self.template_data,
                    action=req.href.openid('login'),
                    images=img_path)

        return 'openidlogin.html', data, None

    # FIXME: needs work
    def _save_referer(self, req):
        for candidate in (req.args.get('referer'), req.get_header('Referer')):
            referer = sanitize_referer(candidate, req.base_url)
            if referer:
                req.session['authopenid.referer'] = referer
                break
        else:
            req.session.pop('authopenid.referer', None)

    def _get_referer(self, req):
        for candidate in [req.session.pop('authopenid.referer', None),
                          req.args.get('referer'),
                          req.get_header('Referer')]:
            referer = sanitize_referer(candidate, req.base_url)
            if referer:
                if referer.startswith(req.abs_href('openid')):
                    # don't redirect back to any of our pages
                    break
                return referer
        return self.env.abs_href()
