# -*- coding: utf-8 -*-
from __future__ import absolute_import

import sys
if sys.version_info >= (2, 7):
    import unittest
else:
    import unittest2 as unittest

from mock import Mock, patch
import webob

from trac.test import EnvironmentStub
from trac.web.api import Request
from trac.web.chrome import Chrome
from trac.web.session import DetachedSession

from authopenid.api import FULL_NAME, OpenIDIdentifier

class TestOpenIDLegacyRegistrationModule(unittest.TestCase):
    def setUp(self):
        from authopenid.authopenid import AuthOpenIdPlugin
        # make sure the identifier, and UserLogin are available
        from authopenid import identifier_store, userlogin ; 'SIDE-EFFECTS'

        self.env = EnvironmentStub(enable=[
            'trac.*',
            'authopenid.identifier_store.*',
            'authopenid.userlogin.*',
            ])
        #assert self.env.dburi == 'sqlite::memory:'

        # Instantiate the AuthOpenIdPlugin.
        dummy_authz_policy = Mock()
        # Prevent "No OpenID authorization_polices are configured" error.
        with patch.object(AuthOpenIdPlugin, 'authorization_policies',
                          [dummy_authz_policy]):
            AuthOpenIdPlugin(self.env)

        self.req = MockRequest()
        Chrome(self.env).prepare_request(self.req)

    def tearDown(self):
        self.env.destroy_db()

    def get_registration_module(self):
        from authopenid.register import OpenIDLegacyRegistrationModule
        return OpenIDLegacyRegistrationModule(self.env)

    def create_user(self, username, identifier=None):
        from authopenid.identifier_store import OpenIDIdentifierStore
        ds = DetachedSession(self.env, username)
        ds['name'] = username
        if identifier:
            ds[OpenIDIdentifierStore.identifier_skey] = ident(identifier)
        ds.save()

    def test_register_user(self):
        identifier = ident('=joe', {FULL_NAME: 'joseph'})
        reg = self.get_registration_module()
        with self.assertRaises(Redirected):
            reg.register_user(self.req, identifier)

        ds = DetachedSession(self.env, 'joseph')
        self.assertEqual(ds['name'], 'joseph')

    def test_register_user_uniquifies_name(self):
        self.create_user('Joseph', '=not*joe')
        identifier = ident('=joe', {FULL_NAME: 'Joseph'})
        reg = self.get_registration_module()
        with self.assertRaises(Redirected):
            reg.register_user(self.req, identifier)

        ds = DetachedSession(self.env, 'Joseph (2)')
        self.assertEqual(ds['name'], 'Joseph')

    def test_register_user_lowercases_name(self):
        self.env.config.set('trac', 'ignore_auth_case', True)
        self.create_user('joseph', '=not*joe')
        identifier = ident('=joe', {FULL_NAME: 'Joseph'})
        reg = self.get_registration_module()
        with self.assertRaises(Redirected):
            reg.register_user(self.req, identifier)

        ds = DetachedSession(self.env, 'joseph (2)')
        self.assertEqual(ds['name'], 'Joseph')


def ident(s, *args, **kwargs):
    identifier = OpenIDIdentifier(s)
    identifier.signed_data.update(*args, **kwargs)
    return identifier

class Redirected(Exception):
    @property
    def url(self):
        return self.args[0]

class MockRequest(Request):
    def __init__(self, base_url='http://example.net/', authname='anonymous'):
        environ = webob.Request.blank(base_url).environ
        start_response = Mock(name='start_response', spec=())
        Request.__init__(self, environ, start_response)
        self.authname = authname
        self.locale = None

    def redirect(self, url, permanent=False):
        raise Redirected(url, permanent)

    @property
    def start_response(self):
        return self._start_response
