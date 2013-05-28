from __future__ import absolute_import

# FIXME: this is all currently broken and ready for refactoring

try:
    import json
except ImportError:
    import simplejson as json           # python < 2.6
import urllib

from authopenid.api import NotAuthorized
from authopenid.interfaces import (
    IOpenIDAuthorizationProvider,
    )


class ExternalAuthorizer(Component):
    """ Implements the legacy ``check_list`` authorization.

    XXX: Could use some cleanup of config args.
    FIXME: Document: No long strips scheme/slashes from identifier.
    FIXME: Change default value for ``check_list_key``
    FIXME: Return 403 if not authorized?
    FIXME: Provide alternative implementation for b/c
    """
    implements(IOpenIDAuthorizationProvider, IUsernameProvider)

    # IOpenIDAuthorizationProvider
    def authorize(self, claimed_identifier, extension_data=None):
        self._check(claimed_identifier, extension_data)

    # IUsernameProvider
    def get_username(self, claimed_identifier, extension_data=None):
        try:
            return self._check(claimed_identifier, extension_data)
        except NotAuthorized:
            pass

    def _check(self, claimed_identifier, extension_data=None):
        # FIXME: cache the result of the check (for the duration of
        # the current request)
        plugin = AuthOpenIdPlugin(self.env)

        service_url = plugin.check_list
        the_key = plugin.check_list_key
        username_key = plugin.check_list_username

        if not service_url or not the_key:
            # nothing to check
            return

        email = extension_data and extension_data.get('email')
        params = { the_key: claimed_identifier }
        if email:
            params['email'] = email
        url = service_url + '?' + urllib.urlencode(params)
        log.debug("Calling external authenticator %s", url)

        try:
            result = json.load(urllib.urlopen(url))
            if not result.get(the_key):
                raise NotAuthorized()
            if username_key:
                username = unicode(result[username_key])
                if not username:
                    log.debug("External authenticator didn't return a username")
                    raise NotAuthorized()
                return username
        except NotAuthorized:
            raise
        except Exception, ex:
            log.error("Error checking external authenticator: %s", ex)
            raise NotAuthorized()
