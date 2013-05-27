from __future__ import absolute_import

try:
    import json
except ImportError:
    import simplejson as json           # python < 2.6
import urllib

from openid.extensions import sreg, ax, pape

from authopenid.exceptions import NotAuthorized
from authopenid.interfaces import (
    IOpenIDExtensionProvider,
    IAuthorizationProvider,
    )

class WhitelistAuthorizer(Component):
    """ Implements whitelist/blacklist authorization.

    XXX: Maybe move the email checking into a separate component.
    """
    implements(IAuthorizationProvider)

    def __init__(self):
        plugin = AuthOpenIdPlugin(self.env)
        self.white_list_re = _compile_patterns(plugin.white_list)
        self.black_list_re = _compile_patterns(plugin.black_list)
        self.email_white_list_re = _compile_patterns(plugin.email_white_list)

    def authorize(self, claimed_identifier, extension_data=None):
        log = self.log

        if self.white_list_re:
            log.debug("checking white_list")
            if not self.white_list_re.match(claimed_identifier):
                log.info("white_list does not match identity %r",
                         claimed_identifier)
                raise NotAuthorized()

        if self.black_list_re:
            log.debug("checking black_list")
            if self.black_list_re.match(claimed_identifier):
                log.info("black_list blocks identity %r", claimed_identifier)
                raise NotAuthorized()

        if self.email_white_list_re:
            # FIXME: ensure that email address was signed?
            email = extension_data and extension_data.get('email')
            log.debug("checking email_white_list")
            if not email or not self.email_white_list_re.match(email):
                log.info("email_white_list does not match %r", email)
                raise NotAuthorized()

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


class ExternalAuthorizer(Component):
    """ Implements the legacy ``check_list`` authorization.

    XXX: Could use some cleanup of config args.
    FIXME: Document: No long strips scheme/slashes from identifier.
    FIXME: Change default value for ``check_list_key``
    FIXME: Return 403 if not authorized?
    FIXME: Provide alternative implementation for b/c
    """
    implements(IAuthorizationProvider, IUsernameProvider)

    # IAuthorizationProvider
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

class SREGExtensionProvider(Component):
    implements(IOpenIDExtensionProvider)

    def add_to_auth_request(self, req, auth_request):
        plugin = AuthOpenIdPlugin(self.env)

        # Let the sreg policy be configurable
        sreg_opt = []
        sreg_req = []
        sreg_fields = ['fullname', 'email']
        if plugin.sreg_required:
            sreg_req = sreg_fields
        else:
            sreg_opt = sreg_fields
        if plugin.use_nickname_as_authname:
            sreg_req.append('nickname')

        sreg_request = sreg.SRegRequest(optional=sreg_opt, required=sreg_req)
        auth_request.addExtension(sreg_request)

    def parse_response(self, response):
        return sreg.SRegResponse.fromSuccessResponse(response) or {}

class AXExtensionProvider(Component):
    implements(IOpenIDExtensionProvider)

    ax_attrs=dict(
        email='http://schema.openid.net/contact/email',
        email2='http://axschema.org/contact/email',
        firstname='http://axschema.org/namePerson/first',
        # FIXME: not b/c.  Enable once we match on identity url
        #middlename='http://axschema.org/namePerson/middle',
        lastname='http://axschema.org/namePerson/last',

        nickname='http://axschema.org/namePerson/friendly',
        fullname='http://axschema.org/namePerson', # yahoo
        )

    def add_to_auth_request(self, req, auth_request):
        ax_request = ax.FetchRequest()
        for alias, uri in self.openid_ax_attrs.items():
            attr_info = ax.AttrInfo(uri, required=True, alias=alias)
            ax_request.add(attr_info)
        auth_request.addExtension(ax_request)

    def parse_response(self, response):
        ax_response = ax.FetchResponse.fromSuccessResponse(response)
        if not ax_response:
            return {}

        data = dict((alias, ax_response.getSingle(uri))
                    for alias, uri in self.ax_attrs.items()
                    if ax_response.count(url) > 0)

        if 'email' not in data and 'email2' in data:
            data['email'] = data.pop('email2')

        if 'fullname' not in data:
            name_parts = 'firstname', 'middlename', 'lastname'
            data['fullname'] = ' '.join(ax_info(part) for part in name_parts
                                        if part in data)
        return dict((k, data[k]) for k in ('email', 'fullname', 'nickname')
                    if k in data)


class PAPEExtensionProvider(Component):
    implements(IOpenIDExtensionProvider)

    # FIXME: this needs some cleanup

    def add_to_auth_request(self, req, auth_request):
        plugin = AuthOpenIdPlugin(self.env)

        requested_policies = []
        if plugin.pape_method:
            requested_policies.append(self.pape_method)

        pape_method = req.args.get('pape_method')
        if pape_method:
            requested_policies.append(pape_method)

        if requested_policies:
            pape_request = pape.Request(requested_policies)
            auth_request.addExtension(pape_request)

    def parse_response(self, response):
        # FIXME: should require pape_method in response?
        return {}
