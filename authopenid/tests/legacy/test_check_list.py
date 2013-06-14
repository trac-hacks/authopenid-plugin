# -*- coding: utf-8 -*-
from __future__ import absolute_import

try:
    import json
except ImportError:                     # pragma: no cover
    import simplejson as json           # python < 2.6
from StringIO import StringIO
import unittest
if not hasattr(unittest, 'skipIf'):     # pragma: no cover
    import unittest2 as unittest
from urlparse import urlparse, parse_qsl

from mock import patch, call

from trac.test import EnvironmentStub

from authopenid.api import EMAIL_ADDRESS, OpenIDIdentifier

class CheckListAuthorizer(unittest.TestCase):
    def setUp(self):
        self.env = EnvironmentStub()

    def make_one(self):
        from authopenid.legacy.check_list import CheckListAuthorizer
        return CheckListAuthorizer(self.env)

    def test_check_list_url(self):
        self.env.config.set('openid', 'check_list', 'http://example.com/c')
        auth = self.make_one()
        with patch.object(auth, 'urlopen') as urlopen:
            auth.is_trusted(None, ident('=id'))
        self.assertEquals(urlopen.mock_calls[0],
                          call('http://example.com/c?check_list=%3Did'))

    def test_check_list_url_with_email(self):
        self.env.config.set('openid', 'check_list', 'http://example.com/c')
        email = 'foo@example.net'
        identifier = '=id'
        auth = self.make_one()
        with patch.object(auth, 'urlopen') as urlopen:
            auth.is_trusted(None, ident(identifier, {EMAIL_ADDRESS: email}))
        (url,), _ = urlopen.call_args
        query = urlparse(url).query
        args = parse_qsl(query, keep_blank_values=True, strict_parsing=True)
        self.assertEquals(dict(args),
                          {'check_list': identifier, 'email': email})

    def test_defaults_to_trusted(self):
        auth = self.make_one()
        self.assertTrue(auth.is_trusted(None, ident('=id')))

    def test_is_trusted_pass(self):
        self.env.config.set('openid', 'check_list', 'http://example.com/c')
        auth = self.make_one()
        with patch.object(auth, 'urlopen') as urlopen:
            urlopen.return_value = StringIO(json.dumps({'check_list': True}))
            self.assertTrue(auth.is_trusted(None, ident('=id')))

    def test_is_trusted_fail(self):
        self.env.config.set('openid', 'check_list', 'http://example.com/c')
        auth = self.make_one()
        with patch.object(auth, 'urlopen') as urlopen:
            urlopen.return_value = StringIO(json.dumps({'check_list': 0}))
            self.assertFalse(auth.is_trusted(None, ident('=id')))

    def test_is_trusted_pass_with_username(self):
        self.env.config.set('openid', 'check_list', 'http://example.com/c')
        self.env.config.set('openid', 'check_list_username', 'username')
        auth = self.make_one()
        with patch.object(auth, 'urlopen') as urlopen:
            urlopen.return_value = StringIO(json.dumps({'check_list': 1,
                                                        'username': 'joe'}))
            self.assertTrue(auth.is_trusted(None, ident('=id')))

    def test_is_trusted_fails_if_no_username(self):
        self.env.config.set('openid', 'check_list', 'http://example.com/c')
        self.env.config.set('openid', 'check_list_username', 'username')
        auth = self.make_one()
        with patch.object(auth, 'urlopen') as urlopen:
            urlopen.return_value = StringIO(json.dumps({'check_list': True}))
            self.assertFalse(auth.is_trusted(None, ident('=id')))

    def test_is_trusted_fails_if_empty_username(self):
        self.env.config.set('openid', 'check_list', 'http://example.com/c')
        self.env.config.set('openid', 'check_list_username', 'username')
        auth = self.make_one()
        with patch.object(auth, 'urlopen') as urlopen:
            urlopen.return_value = StringIO(json.dumps({'check_list': True,
                                                        'username': ''}))
            self.assertFalse(auth.is_trusted(None, ident('=id')))

    def test_is_trusted_invalid_response(self):
        self.env.config.set('openid', 'check_list', 'http://example.com/c')
        auth = self.make_one()
        with patch.object(auth, 'urlopen') as urlopen:
            urlopen.return_value = StringIO('not json')
            self.assertFalse(auth.is_trusted(None, ident('=id')))

    def test_suggest_username_pass_no_username(self):
        self.env.config.set('openid', 'check_list', 'http://example.com/c')
        self.env.config.set('openid', 'check_list_username', 'username')
        req = None                      # FIXME
        auth = self.make_one()
        with patch.object(auth, 'urlopen') as urlopen:
            urlopen.return_value = StringIO(json.dumps({'check_list': 'yes',
                                                        'username': 'joe'}))
            self.assertIs(auth.suggest_username(req, ident('=id')), 'joe')

    def test_suggest_username_pass_no_username(self):
        self.env.config.set('openid', 'check_list', 'http://example.com/c')
        self.env.config.set('openid', 'check_list_username', 'username')
        req = None                      # FIXME
        auth = self.make_one()
        with patch.object(auth, 'urlopen') as urlopen:
            urlopen.return_value = StringIO(json.dumps({'check_list': True}))
            self.assertIs(auth.suggest_username(req, ident('=id')), None)

    @unittest.expectedFailure
    def test_caching(self):
        self.env.config.set('openid', 'check_list', 'http://example.com/c')
        auth = self.make_one()
        req = response = None           # FIXME:
        with patch.object(auth, 'urlopen') as urlopen:
            urlopen.return_value = StringIO(json.dumps({'check_list': True}))
            auth.is_trusted(response, ident('=id'))
            auth.suggest_username(req, ident('=id'))
        self.assertEquals(urlopen.call_count, 1)

def ident(s, *args, **kwargs):
    identifier = OpenIDIdentifier(s)
    identifier.signed_data.update(*args, **kwargs)
    return identifier
