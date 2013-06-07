# -*- coding: utf-8 -*-
from __future__ import absolute_import

import unittest
if not hasattr(unittest, 'skipIf'):
    import unittest2 as unittest

from trac.test import EnvironmentStub

from authopenid.api import EMAIL_ADDRESS, OpenIDIdentifier

class TestWhitelistAuthorizer(unittest.TestCase):
    def setUp(self):
        self.env = EnvironmentStub()

    def make_one(self):
        from authopenid.legacy.whitelist import WhitelistAuthorizer
        return WhitelistAuthorizer(self.env)

    def assert_is_trusted(self, oid_identifier):
        auth = self.make_one()
        self.assertTrue(auth.is_trusted(None, oid_identifier),
                        "expected %r to be trusted" % oid_identifier)

    def assert_is_not_trusted(self, oid_identifier):
        auth = self.make_one()
        self.assertFalse(auth.is_trusted(None, oid_identifier),
                         "expected %r not to be trusted" % oid_identifier)

    def test_defaults_to_trusted(self):
        self.assert_is_trusted(ident('=id'))

    def test_white_list(self):
        self.env.config.set('openid', 'white_list', '=fred, =joe')
        self.assert_is_trusted(ident('=fred'))
        self.assert_is_not_trusted(ident('=freddy'))
        self.assert_is_trusted(ident('=joe'))

    def test_black_list(self):
        self.env.config.set('openid', 'black_list', '=x*')
        self.assert_is_trusted(ident('=fred'))
        self.assert_is_not_trusted(ident('=xavier'))

    def test_email_white_list(self):
        self.env.config.set('openid', 'email_white_list', '*@example.com')
        self.assert_is_trusted(
            ident('=fred', {EMAIL_ADDRESS: 'fred@example.com'}))
        self.assert_is_not_trusted(
            ident('=fred', {EMAIL_ADDRESS: 'fred@example.net'}))

    def test_email_white_list_does_not_trust_if_no_email(self):
        self.env.config.set('openid', 'email_white_list', '*@example.com')
        self.assert_is_not_trusted(ident('=fred'))

class Test_compile_patterns(unittest.TestCase):
    def compile(self, patterns):
        from authopenid.legacy.whitelist import _compile_patterns
        return _compile_patterns(patterns)

    def test_strings(self):
        regexp = self.compile(['a', 'bear'])
        self.assertTrue(regexp.match('a'))
        self.assertTrue(regexp.match('bear'))
        self.assertFalse(regexp.match('b'))
        self.assertFalse(regexp.match('A'))
        self.assertFalse(regexp.match('ear'))

    def test_wildcard(self):
        regexp = self.compile(['a*', 'be*ar*'])
        self.assertTrue(regexp.match('a'))
        self.assertTrue(regexp.match('ab'))
        self.assertTrue(regexp.match('bear'))
        self.assertTrue(regexp.match('beard'))
        self.assertTrue(regexp.match('becareful'))
        self.assertFalse(regexp.match('b'))
        self.assertFalse(regexp.match('ba'))
        self.assertFalse(regexp.match('A'))
        self.assertFalse(regexp.match('ear'))

def ident(s, *args, **kwargs):
    identifier = OpenIDIdentifier(s)
    identifier.signed_data.update(*args, **kwargs)
    return identifier
