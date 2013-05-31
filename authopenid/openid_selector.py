# -*- coding: utf-8 -*-
""" Implements the openid-selector_ OpenID selector form

.. _openid-selector: https://code.google.com/p/openid-selector/
"""
from __future__ import absolute_import

from genshi.core import Stream
from genshi.filters.transform import Transformer

from trac.core import Component, implements
from trac.config import ChoiceOption, ListOption, Option
from trac.web.api import ITemplateStreamFilter
from trac.web.chrome import add_script, add_stylesheet, Chrome

class OpenIDSelector(Component):
    implements(ITemplateStreamFilter)

    signup_link = Option(
        'openid', 'signup', 'http://openid.net/get/',
        """Signup link""")

    whatis_link = Option(
        'openid', 'whatis', 'http://openid.net/what/',
        """What is OpenId link.""")

    providers = ListOption(
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

    def __init__(self):
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

    def filter_stream(self, req, method, filename, stream, data):
        if filename.startswith('openid'):
            # FIXME: rename
            add_stylesheet(req, 'authopenid/openid-selector/css/openid.css')
            add_script(req, 'authopenid/openid-selector/js/openid-jquery.js')

            tmpl_data = dict(
                self.template_data,
                images=req.href.chrome(
                    'authopenid/openid-selector/images') + '/')
            tmpl_data.update(data)

            # Load our bits from template file
            # FIXME: check that load_template does caching
            tmpl = Chrome(self.env).load_template('openid-selector.html')
            ts = Stream(list(tmpl.generate(**tmpl_data)))
            scripts = ts.select('//head[1]/script')
            formbody = ts.select('//form[1]/*')

            stream |= Transformer('//head[1]').append(scripts)
            stream |= Transformer(
                '//form[@id="openid_form"]/*').replace(formbody)

        return stream
