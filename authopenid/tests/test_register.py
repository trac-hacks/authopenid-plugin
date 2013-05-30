# -*- coding: utf-8 -*-
from __future__ import absolute_import


from StringIO import StringIO
from urlparse import urlparse
import sys
if sys.version_info >= (2, 7):
    import unittest
else:
    import unittest2 as unittest

from mock import Mock, patch

from trac.test import EnvironmentStub
from trac.web.api import Request
from trac.web.chrome import Chrome
from trac.web.session import DetachedSession

from authopenid.api import (
    FULL_NAME,
    OpenIDIdentifier,
    )

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

DEFAULT_ENVIRON = {
    'REQUEST_METHOD': 'POST',
    'SERVER_NAME': 'example.net',
    #'SERVER_PORT': '80',
    #'SCRIPT_NAME': '',
    'PATH_INFO': '',
    #'QUERY_STRING': '',
    #'CONTENT_TYPE': '',
    'SERVER_PROTOCOL': 'HTTP/1.1',
    'wsgi.version': (1,0),
    #'wsgi.url_scheme': 'http',
    'wsgi.multithread': False,
    'wsgi.multiprocess': False,
    'wsgi.run_once': False,
    }

class MockRequest(Request):
    def __init__(self, base_url='http://example.net/',
                 authname='anonymous',
                 **extra_env):
        environ = dict(DEFAULT_ENVIRON)
        environ.update({
            'wsgi.input': StringIO(),
            'wsgi.errors': StringIO(),
            })
        environ.update(extra_env)
        if base_url:
            base = urlparse(base_url)
            if base.netloc:
                environ['HTTP_HOST'] = base.netloc
            environ['SERVER_PORT'] = base.port \
                                     or (443 if base.scheme == 'https' else 80)
            environ['wsgi.url_scheme'] = base.scheme or 'http'
            environ['SCRIPT_NAME'] = base.path or ''

        Request.__init__(self, environ, self.mock_start_response)
        self.authname = authname
        self.locale = None

    def mock_start_response(self, status, headers):
        self.mock_response = status, headers

    def redirect(self, url, permanent=False):
        raise Redirected(url, permanent)
