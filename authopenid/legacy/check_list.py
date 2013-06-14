# -*- coding: utf-8 -*-
""" Legacy support for 'check_list' web API access checks
"""
from __future__ import absolute_import

try:
    import json
except ImportError:                     # pragma: no cover
    import simplejson as json           # python < 2.6
import urllib

from trac.core import Component, implements
from trac.config import Option

from authopenid.api import (
    EMAIL_ADDRESS,
    IOpenIDAuthnRequestListener,
    IOpenIDRegistrationParticipant,
    )

class CheckListAuthorizer(Component):
    """ Legacy support for 'check_list' web API access checks

    Configuration is a bit wonky, but we're just copying the original...

    XXX: Could use some cleanup of config args.
    FIXME: Document: No longer strips scheme/slashes from identifier.
    FIXME: Change default value for ``check_list_key``
    FIXME: Return 403 if not authorized?
    FIXME: Provide alternative implementation for b/c
    """
    implements(IOpenIDAuthnRequestListener, IOpenIDRegistrationParticipant)

    check_list = Option('openid', 'check_list', None,
            """JSON service for openid check.""")

    check_list_key = Option('openid', 'check_list_key', 'check_list',
            """Key for openid Service.""")

    check_list_username = Option('openid', 'check_list_username', None,
            """Username for openid Service.""")


    urlopen = classmethod(urllib.urlopen) # testing

    # IOpenIDAuthnRequestListener
    def prepare_authn_request(self, response, auth_request):
        pass                            # pragma: no cover

    def parse_response(self, response, oid_identifier):
        pass                            # pragma: no cover

    def is_trusted(self, response, oid_identifier):
        # FIXME: need req
        req = None
        trusted, username = self._check(req, oid_identifier)
        return trusted

    # IOpenIDRegistrationParticipant
    def authorize(self, req, oid_identifier):
        pass                            # pragma: no cover

    def suggest_username(self, req, oid_identifier):
        trusted, username = self._check(req, oid_identifier)
        return username if trusted else None

    def get_user_data(self, req, oid_identifier):
        pass                            # pragma: no cover

    def _check(self, req, oid_identifier):
        # FIXME: cache the result of the check (for the duration of
        # the current request)
        log = self.log

        service_url = self.check_list
        the_key = self.check_list_key
        username_key = self.check_list_username

        if not service_url or not the_key:
            # nothing to check
            return True, None

        params = { the_key: unicode(oid_identifier) }
        email = oid_identifier.signed_data.get(EMAIL_ADDRESS)
        if email:
            params['email'] = email
        url = service_url + '?' + urllib.urlencode(params)
        log.debug("Calling external authenticator %s", url)

        trusted = False
        username = None
        try:
            result = json.load(self.urlopen(url))
            trusted = bool(result.get(the_key))
            if trusted and username_key:
                username = unicode(result[username_key])
                if not username:
                    log.debug("External authenticator didn't return a username")
                    trusted = False
        except Exception, ex:
            log.error("Error checking external authenticator: %s", ex)
            trusted = False
        return trusted, username
