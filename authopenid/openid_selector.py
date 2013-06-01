# -*- coding: utf-8 -*-
""" Implements the openid-selector_ OpenID selector form

.. _openid-selector: https://code.google.com/p/openid-selector/
"""
from __future__ import absolute_import

try:
    import json
except ImportError:                     # pragma: no cover
    import simplejson as json           # python < 2.6

from trac.core import Component, implements
from trac.config import ChoiceOption, ListOption, Option

from authopenid.api import IOpenIDFancySelector

class OpenIDSelector(Component):
    implements(IOpenIDFancySelector)

    signup_link = Option(
        'openid', 'signup', 'http://openid.net/get/',
        """Signup link""")

    whatis_link = Option(
        'openid', 'whatis', 'http://openid.net/what/',
        """What is OpenId link.""")

    show_providers = ListOption(
        'openid', 'providers', [],
        doc="""Explicit set of providers to offer.

        E.g: google, yahoo, ...""")

    custom_provider_name = Option(
        'openid', 'custom_provider_name', None,
        """ Custom OpenId provider name. """)

    custom_provider_label = Option(
        'openid', 'custom_provider_label', 'Enter your username',
        """ Custom OpenId provider label. """)

    custom_provider_url = Option(
        'openid', 'custom_provider_url', '',
        """ Custom OpenId provider URL. E.g.: http://claimid.com/{username} """)

    custom_provider_image = Option(
        'openid', 'custom_provider_image', '',
        """ Custom OpenId provider image. """)

    custom_provider_size = ChoiceOption(
        'openid', 'custom_provider_size', ('small', 'large'),
        doc=""" Custom OpenId provider image size (small or large).""")

    def get_template_data(self, req):
        js_config = {
            'openid': {
                'show_providers': [ p.lower() for p in self.show_providers ],
                'img_path': req.href.chrome('authopenid/openid-selector/images'
                                            ) + '/',
                },
            }
        provider = {
            'size': self.custom_provider_size,
            'name': self.custom_provider_name,
            'label': self.custom_provider_label,
            'url': self.custom_provider_url,
            'image': self.custom_provider_image,
            }
        if all(provider[k] for k in ('size', 'name', 'image', 'url')):
            key = 'providers_%s' % provider['size']
            pid = provider['name'].lower()
            js_config[key] = {pid: provider}

        return {
            'template': 'openid-selector.html',
            'signup': self.signup_link,
            'whatis': self.whatis_link,
            'js_config': json.dumps(js_config),
            }
