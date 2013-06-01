# -*- coding: utf-8 -*-
""" A preference panel for managing OpenID identifiers link to the account
"""
from __future__ import absolute_import

from genshi.core import escape
from genshi.builder import tag
from trac.core import Component, implements
from trac.prefs import IPreferencePanelProvider
from trac.web import chrome
from trac.web.main import IRequestHandler

from authopenid.api import (
    NotAuthorized,
    DiscoveryFailure,
    OpenIDIdentifierInUse,
    UserNotFound,
    )

from authopenid.authopenid import AuthOpenIdPlugin

class OpenIDPreferencePanel(Component):
    """ A preference panel which allows users to dis/associate their
    trac accounts with OpenID identifiers

    .. WARNING:: Currently a trac account can only be connected to a
        single OpenID indentifier at a time.  This will be fixed at
        some point.
    """
    implements(IPreferencePanelProvider, IRequestHandler)

    # FIXME: make a special property for this?
    # identifier_store = OtherConfig(AuthOpenIdPlugin, 'identifer_store')
    @property
    def identifier_store(self):
        return AuthOpenIdPlugin(self.env).identifier_store
    @property
    def openid_consumer(self):
        return AuthOpenIdPlugin(self.env).openid_consumer

    #IPreferencePanelProvider
    def get_preference_panels(self, req):
        # FIXME: How to avoid "Unknown preference panel" error upon logout?
        if req.authname and req.authname != 'anonymous':
            yield 'openid', 'OpenID'

    def render_preference_panel(self, req, panel):
        if not req.authname or req.authname == 'anonymous':
            chrome.add_warning(req, "Not logged in!?!")
            return self._panel(req)

        if req.method == 'POST':
            action = req.args.get('action')
            if action == 'associate':
                return self._do_associate(req, panel)
            elif action == 'delete_associations':
                return self._do_delete(req, panel)
            else:
                self.log.warning("Unknown action %r", action)

        return self._panel(req)

    #IRequestHandler
    def match_request(self, req):
        return req.path_info == '/openid/associate'

    def process_request(self, req):
        if not req.authname or req.authname == 'anonymous':
            self.log.warning("/openid/associate: not logged in!?!")
            return req.redirect(req.href())

        return self._do_openid_response(req)

    def _do_associate(self, req, panel):
        username = req.authname
        oid_identifier = req.args.getfirst('openid_identifier', '')
        if not oid_identifier:
            chrome.add_warning(req, "Enter an OpenID identifier")
            return self._panel(req)

        return_to = req.abs_href.openid('associate')
        try:
            return self.openid_consumer.begin(req, oid_identifier, return_to)
        except DiscoveryFailure as exc:
            chrome.add_warning(req, exc)
            return self._panel(req)

    def _do_openid_response(self, req):
        """Handle the redirect from the OpenID server.
        """
        username = req.authname

        try:
            identifier = self.openid_consumer.complete(req)
        except NegativeAssertion as exc:
            chrome.add_warning(req, exc)
            return req.redirect(req.href.prefs('openid'))

        # FIXME: should authz checks be performed only for new accounts?
        try:
            self._check_authorization(req, identifier)
        except NotAuthorized as exc:
            chrome.add_warning(req, exc)
            return req.redirect(req.href.prefs('openid'))

        try:
            self.identifier_store.add_identifier(username, identifier)
        except OpenIDIdentifierInUse as exc:
            self.log.warning("/openid/associate: %s", exc)
            chrome.add_warning(
                req, escape("OpenID %s is already associated by another user")
                % tag.code(identifier))
        except UserNotFound as exc:
            self.log.warning("/openid/associate: %s", exc)
            chrome.add_warning(req, exc)
        else:
            chrome.add_notice(
                req, escape('Added OpenID %s') % tag.code(identifier))
            # FIXME: this is a hack until identifier_store is fixed
            # so that it can add identifier to the currently logged in
            # user.  (Right now, req.session.save() at the end of the
            # request overwrites changes.)
            req.session.get_session(username, authenticated=True)
        return req.redirect(req.href.prefs('openid'))

    def _do_delete(self, req, panel):
        username = req.authname
        associations = req.args.getlist('association')
        if len(associations) == 0:
            chrome.add_warning(req, "No OpenIDs selected, none deleted.")
            return self._panel(req)

        for oid_identifier in associations:
            self.identifier_store.discard_identifier(username, oid_identifier)
            chrome.add_notice(
                req, escape("Deleted OpenID %s") % tag.code(oid_identifier))
        return self._panel(req)


    # FIXME:
    def _check_authorization(self, req, oid_identifier):
        return AuthOpenIdPlugin(self.env)._check_authorization(req, oid_identifier)

    def _panel(self, req):
        # FIXME:
        fancy_selector = AuthOpenIdPlugin(self.env).fancy_selector

        data = {
            'openid_identifiers':
            self.identifier_store.get_identifiers(req.authname),
            }
        if fancy_selector:
            data['selector'] = fancy_selector.get_template_data(req)

        return 'openid_preferences.html', data
