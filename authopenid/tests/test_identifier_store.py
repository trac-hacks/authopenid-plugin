from __future__ import absolute_import

import unittest
if not hasattr(unittest, 'skipIf'):
    import unittest2 as unittest

from trac.test import EnvironmentStub
from trac.web.session import DetachedSession


from authopenid.api import (
    OpenIDIdentifier,
    OpenIDIdentifierInUse,
    UserNotFound,
    )
from authopenid.compat import modernize_env

class TestOpenIDIdentifierStore(unittest.TestCase):
    def setUp(self):
        self.env = EnvironmentStub()
        #assert self.env.dburi == 'sqlite::memory:'

    def tearDown(self):
        self.env.destroy_db()

    def get_identifier_store(self):
        from authopenid.identifier_store import OpenIDIdentifierStore
        return OpenIDIdentifierStore(self.env)

    def create_user(self, username, identifier=None, last_visit=None):
        from authopenid.identifier_store import OpenIDIdentifierStore
        ds = DetachedSession(self.env, username)
        ds['name'] = username
        if identifier:
            ds[OpenIDIdentifierStore.identifier_skey] = ident(identifier)
        ds.save()
        if last_visit is not None:
            with modernize_env(self.env).db_transaction as db:
                db("UPDATE session SET last_visit=%s"
                   " WHERE sid=%s and authenticated=1",
                   (last_visit, username))

    def test_get_user(self):
        self.create_user('joe', '=joe')
        store = self.get_identifier_store()
        self.assertEqual(store.get_user(ident('=joe')), 'joe')
        self.assertIs(store.get_user(ident('=notjoe')), None)

    def test_get_user_returns_most_recent_if_multiple_matches(self):
        self.create_user('old', '=id', last_visit=1000)
        self.create_user('new', '=id', last_visit=2000)
        store = self.get_identifier_store()
        with LogCapture() as l:
            self.assertEqual(store.get_user(ident('=id')), 'new')
        self.assertEqual(len(l.records), 1)
        self.assertRegexpMatches(
            l.records[0].getMessage(),
            "\AMultiple users share the same openid identifier:")


    def test_get_identifiers(self):
        self.create_user('joe', '=joe')
        self.create_user('bob')
        store = self.get_identifier_store()
        self.assertEqual(store.get_identifiers('joe'), set(['=joe']))
        self.assertEqual(store.get_identifiers('bob'), set())

    def test_get_identifiers_raises_user_not_found(self):
        store = self.get_identifier_store()
        with self.assertRaises(UserNotFound):
            store.get_identifiers('Bob')

    def test_get_identifiers_ignore_auth_case(self):
        self.env.config.set('trac', 'ignore_auth_case', True)
        self.create_user('joe', '=joe')
        store = self.get_identifier_store()
        self.assertEqual(store.get_identifiers('jOe'), set(['=joe']))

    def test_add_identifier(self):
        self.create_user('bob')
        store = self.get_identifier_store()

        store.add_identifier('bob', ident('=bob'))
        self.assertEqual(store.get_user(ident('=bob')), 'bob')

    def test_add_identifier_adds_identifier(self):
        self.create_user('bob', '=bob')
        store = self.get_identifier_store()
        store.add_identifier('bob', ident('=bob*alt'))
        self.assertEqual(store.get_user(ident('=bob*alt')), 'bob')

    def test_add_identifier_raises_user_not_found(self):
        store = self.get_identifier_store()
        self.create_user('bob')
        with self.assertRaises(UserNotFound):
            store.add_identifier('filbert', ident('=filbert'))

    def test_add_identifier_raises_openid_identifier_in_use(self):
        store = self.get_identifier_store()
        self.create_user('bob', '=bob')
        self.create_user('rob')
        with self.assertRaises(OpenIDIdentifierInUse):
            store.add_identifier('rob', ident('=bob'))

    def test_add_identifier_ignore_auth_case(self):
        self.env.config.set('trac', 'ignore_auth_case', True)
        self.create_user('joe', '=joe')
        store = self.get_identifier_store()
        store.add_identifier('JOE', ident('=JOE'))
        self.assertEqual(store.get_user(ident('=JOE')), 'joe')

    def test_discard_identifier(self):
        self.create_user('joe', '=joe')
        store = self.get_identifier_store()
        store.discard_identifier('joe', ident('=joe'))
        self.assertEqual(store.get_identifiers('joe'), set())

    def test_discard_identifier_no_match(self):
        self.create_user('joe', '=joe')
        store = self.get_identifier_store()
        store.discard_identifier('joe', ident('=bob'))
        self.assertEqual(store.get_identifiers('joe'), set(['=joe']))

    def test_discard_identifier_no_identifier(self):
        self.create_user('joe')
        store = self.get_identifier_store()
        self.assertEqual(store.get_identifiers('joe'), set())
        store.discard_identifier('joe', ident('=joe'))
        self.assertEqual(store.get_identifiers('joe'), set())

    def test_discard_identifier_raises_user_not_found(self):
        store = self.get_identifier_store()
        with self.assertRaises(UserNotFound):
            store.discard_identifier('filbert', ident('=filbert'))

    def test_discard_identifier_ignore_auth_case(self):
        self.env.config.set('trac', 'ignore_auth_case', True)
        self.create_user('joe', '=joe')
        store = self.get_identifier_store()
        store.discard_identifier('JOE', ident('=joe'))
        self.assertEqual(store.get_identifiers('Joe'), set())

def ident(s):
    return OpenIDIdentifier(s)

import logging

class LogCapture(logging.Handler):
    def __init__(self):
        logging.Handler.__init__(self)
        self.records = []

    def emit(self, record):
        self.records.append(record)

    def __enter__(self):
        log = logging.getLogger()
        log.addHandler(self)
        return self

    def __exit__(self, *args):
        log = logging.getLogger()
        log.removeHandler(self)
