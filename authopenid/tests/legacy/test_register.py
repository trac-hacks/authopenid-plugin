# -*- coding: utf-8 -*-
from __future__ import absolute_import

import unittest
if not hasattr(unittest, 'skipIf'):
    import unittest2 as unittest

from trac.test import EnvironmentStub

from authopenid.api import (
    EMAIL_ADDRESS, FULL_NAME, NICKNAME,
    OpenIDIdentifier,
    )

class TestLegacyUsername(unittest.TestCase):
    def setUp(self):
        self.env = EnvironmentStub()

    def make_one(self):
        from authopenid.legacy.register import LegacyUsername
        return LegacyUsername(self.env)

    def assert_suggested_username_is(self, oid_identifier, username):
        req = None
        rp = self.make_one()
        self.assertEquals(rp.suggest_username(req, oid_identifier), username,
                          "unexpect username for %r" % oid_identifier)

    def test_suggest_username(self):
        identifier = ident('=joe', {FULL_NAME: 'Joseph Blow'})
        self.assert_suggested_username_is(identifier, 'Joseph Blow')

    def test_use_nickname_as_authname(self):
        self.env.config.set('openid', 'use_nickname_as_authname', 'true')
        identifier = ident('=joseph', {NICKNAME: 'joe'})
        self.assert_suggested_username_is(identifier, 'joe')

    def test_combined_username(self):
        self.env.config.set('openid', 'combined_username', 'true')
        identifier = ident('=joe', {FULL_NAME: 'Joseph Blow'})
        self.assert_suggested_username_is(identifier, 'Joseph Blow <=joe>')

    def test_fallback_to_identifier(self):
        self.env.config.set('openid', 'combined_username', 'true')
        identifier = ident('=joe', {EMAIL_ADDRESS: 'joe@example.com'})
        self.assert_suggested_username_is(identifier, '=joe')

    def test_strip_protocol(self):
        self.env.config.set('openid', 'strip_protocol', 'true')
        identifier = ident('http://joe.example.com/')
        self.assert_suggested_username_is(identifier, 'joe.example.com/')

    def test_strip_trailing_slash(self):
        self.env.config.set('openid', 'strip_trailing_slash', 'true')
        identifier = ident('http://example.com/joe/')
        self.assert_suggested_username_is(identifier, 'http://example.com/joe')


def ident(s, *args, **kwargs):
    identifier = OpenIDIdentifier(s)
    identifier.signed_data.update(*args, **kwargs)
    return identifier
