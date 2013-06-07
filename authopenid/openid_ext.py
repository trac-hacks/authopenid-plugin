from __future__ import absolute_import

from trac.core import Component, implements
from trac.config import BoolOption, Option

from openid.extensions import sreg, ax, pape

from authopenid.api import (
    EMAIL_ADDRESS, FULL_NAME, NICKNAME,
    IOpenIDAuthnRequestListener,
    )

_FIRST_NAME = 'openid.ax.firstname'
_LAST_NAME = 'openid.ax.lastname'

class OpenIDExtensionProvider(Component):
    implements(IOpenIDAuthnRequestListener)

    abstract = True

    def prepare_authn_request(self, req, auth_request):
        ext_request = self._get_extension_request(req)
        if ext_request:
            auth_request.addExtension(ext_request)

    def is_trusted(self, response, identifier):
        return True

class SREGExtensionProvider(OpenIDExtensionProvider):
    # FIXME: is this needed?
    sreg_required = BoolOption('openid', 'sreg_required', 'false',
        doc="Whether SREG data should be required or optional.")

    FIELDS = {
        EMAIL_ADDRESS: 'email',
        FULL_NAME: 'fullname',
        NICKNAME: 'nickname',
        }

    def _get_extension_request(self, req):
        # XXX: We used to only request the nickname with
        # use_nickname_as_authname was set.  I think it shouldn't
        # cause trouble to request it all the time.

        # Let the sreg policy be configurable
        sreg_fields = list(self.FIELDS.values())
        if self.sreg_required:
            return sreg.SRegRequest(required=sreg_fields)
        else:
            return sreg.SRegRequest(optional=sreg_fields)

    def parse_response(self, response, identifier):
        signed_data = identifier.signed_data
        sreg_response = sreg.SRegResponse.fromSuccessResponse(response)
        if sreg_response:
            for key, field in self.FIELDS.items():
                if field in sreg_response:
                    signed_data.add(key, sreg_response[field])

class AXExtensionProvider(OpenIDExtensionProvider):

    ATTRS = {
        EMAIL_ADDRESS: [
            'http://schema.openid.net/contact/email',
            'http://axschema.org/contact/email',
            ],
        _FIRST_NAME: [
            'http://axschema.org/namePerson/first',
            ],
        # FIXME: not b/c.  Enable once we match on identity url
        #'middlename': ['http://axschema.org/namePerson/middle'],
        _LAST_NAME: [
            'http://axschema.org/namePerson/last',
            ],
        NICKNAME: [
            'http://axschema.org/namePerson/friendly',
            ],
        FULL_NAME: [
            'http://axschema.org/namePerson', # yahoo
            ],
        }

    def _get_extension_request(self, req):
        ax_request = ax.FetchRequest()
        for _, uris in self.ATTRS.items():
            for uri in uris:
                attr_info = ax.AttrInfo(uri, required=True)
                ax_request.add(attr_info)
        return ax_request


    def parse_response(self, response, identifier):
        ax_response = ax.FetchResponse.fromSuccessResponse(response)
        if not ax_response:
            return

        signed_data = identifier.signed_data
        seen = set()
        for key, uris in self.ATTRS.items():
            for uri in uris:
                try:
                    for value in ax_response.get(uri):
                        signed_data.add(key, value)
                except KeyError:
                    pass

        if FULL_NAME not in seen:
            name_parts = _FIRST_NAME, _LAST_NAME
            fullname = ' '.join(signed_data[part] for part in name_parts
                                if part in signed_data)
            if fullname:
                signed_data.add(FULL_NAME, fullname)

class PAPEExtensionProvider(OpenIDExtensionProvider):
    # FIXME: this needs work.  I'm not sure that is is currently useful

    pape_method = Option('openid', 'pape_method', None,
        doc="Default PAPE method to request from OpenID provider.")

    def _get_extension_request(self, req):
        requested_policies = req.args.getlist('pape_method') # FIXME: needed?
        if self.pape_method:
            requested_policies.append(self.pape_method)
        if requested_policies:
            return pape.Request(requested_policies)

    def parse_response(self, response, identifier):
        # FIXME: should require pape_method in response?
        pass
