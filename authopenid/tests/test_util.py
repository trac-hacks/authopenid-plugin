# -*- coding: utf-8 -*-
from __future__ import absolute_import

import unittest
if not hasattr(unittest, 'skip'):
    import unittest2 as unittest

from trac.core import TracError
from trac import db_default
from trac.test import EnvironmentStub

class TestPickleSession(unittest.TestCase):

    skey = 'skey'

    def setUp(self):
        self.sess = dict()

    def make_one(self):
        from authopenid.util import PickleSession
        return PickleSession(self.sess, self.skey)

    def test_persistence(self):
        session = self.make_one()
        session['secret'] = 42
        session = self.make_one()
        self.assertEqual(session['secret'], 42)

    def test_cleanup_when_empty(self):
        session = self.make_one()
        session['secret'] = 42
        self.assertIn(self.skey, self.sess)
        session.clear()
        self.assertNotIn(self.skey, self.sess)

    def test_does_not_puke_on_garbage(self):
        self.sess[self.skey] = (
            "(dp0\nS'id'\np1\nS'44b6b53fc89710f6408b9733'\np2\ns.")
        session = self.make_one()
        self.assertEqual(session, {})

    def test_mutator_with_kwargs(self):
        session = self.make_one()
        session.update(key='value')
        self.assertEquals(session['key'], 'value')

    def test_mutator_name(self):
        session = self.make_one()
        self.assertEquals(session.update.__name__, dict.update.__name__)

BASE_URL = 'http://example.com/trac/'

class Test_sanitize_referer(unittest.TestCase):
    def sanitize(self, referer, base_url=BASE_URL):
        from authopenid.util import sanitize_referer
        return sanitize_referer(referer, base_url)

    def test_base(self):
        self.assertEqual(self.sanitize(BASE_URL), BASE_URL)

    def test_none(self):
        self.assertIs(self.sanitize(None), None)

    def test_relative(self):
        self.assertEqual(self.sanitize('page'), BASE_URL + 'page')

    def test_absolute(self):
        self.assertEqual(self.sanitize(BASE_URL + 'page'), BASE_URL + 'page')

    def test_trailing_slash(self):
        self.assertEqual(self.sanitize(BASE_URL + 'page/'), BASE_URL + 'page/')

    def test_unsafe(self):
        self.assertIs(self.sanitize(BASE_URL + '../page'), None)

    def test_different_scheme(self):
        self.assertIs(self.sanitize(BASE_URL.replace('http:', 'https:')), None)

    def test_different_host(self):
        self.assertIs(self.sanitize(BASE_URL.replace('.com/', '.net/')), None)

class Test_split_path_info(unittest.TestCase):
    def test(self):
        from authopenid.util import split_path_info

        for path, expect in [
            ('/a', '/a'),
            ('/a/', '/a'),
            ('/a/./b', '/a/b'),
            ('/a/../b', '/b'),
            ('/a/../../b', '/b'),
            ]:
            self.assertEqual(split_path_info(path), expect.split('/'))

class TestDbHelpers(unittest.TestCase):
    def setUp(self):
        self.env = EnvironmentStub()

    def tearDown(self):
        self.env.destroy_db()

    def test_get_db_scheme(self):
        from authopenid.util import get_db_scheme
        self.env.config.set('trac', 'database', 'foo:bar')
        self.assertEqual(get_db_scheme(self.env), 'foo')

    def test_list_tables(self):
        from authopenid.util import list_tables

        default_tables = set(table.name for table in db_default.schema)
        self.assertEqual(list_tables(self.env), default_tables)

        self.env.config.set('trac', 'database', 'foodb://')
        with self.assertRaises(TracError):
            list_tables(self.env)

    def test_table_exists(self):
        from authopenid.util import table_exists

        self.assertTrue(table_exists(self.env, 'system'))
        self.assertFalse(table_exists(self.env, 'missing_table'))

class TestMultiDict(unittest.TestCase):

    def make_one(self, *args, **kwargs):
        from authopenid.util import MultiDict
        return MultiDict(*args, **kwargs)

    def test_init_iter(self):
        md = self.make_one([('a', 'a1'), ('b', 'b1'), ('a', 'a2')])
        self.assertEqual(md['a'], 'a1')
        self.assertEqual(md['b'], 'b1')
        self.assertEqual(md.getall('a'), ('a1', 'a2'))

    def test_init_mapping(self):
        md = self.make_one(dict(a='a1'))
        self.assertEqual(md['a'], 'a1')

    def test_init_kw(self):
        md = self.make_one([('a', 'a1')], a='a2')
        self.assertEqual(md.getall('a'), ('a2',))

    def test_add(self):
        md = self.make_one(a='a1')
        md.add('a', 'a2')
        self.assertEqual(md.getall('a'), ('a1', 'a2'))

    def test_getall(self):
        md = self.make_one(a='a1')
        self.assertEqual(md.getall('a'), ('a1',))
        self.assertEqual(md.getall('b'), ())
        self.assertEqual(md.getall('b', 'dflt'), 'dflt')

    def test_getitem(self):
        md = self.make_one([('a', 'a1'), ('a', 'a2')])
        self.assertEqual(md['a'], 'a1')
        with self.assertRaises(KeyError):
            md['b']

    def test_iter(self):
        md = self.make_one([('a', 'a1'), ('a', 'a2')])
        self.assertEqual(list(md), ['a'])

    def test_len(self):
        md = self.make_one()
        self.assertEqual(len(md), 0)
        md.add('a', 'a1')
        self.assertEqual(len(md), 1)

    def test_setitem(self):
        md = self.make_one([('a', 'a1'), ('a', 'a2')])
        md['a'] = 'a3'
        self.assertEqual(md.getall('a'), ('a3',))

    def test_delitem(self):
        md = self.make_one([('a', 'a1'), ('a', 'a2')])
        del md['a']
        self.assertNotIn('a', md)
        with self.assertRaises(KeyError):
            del md['a']

    def test_repr(self):
        from authopenid.util import MultiDict
        md = self.make_one([('a', 'a1'), ('a', 'a2')])
        copy = eval(repr(md))
        self.assertEquals(set(copy.items()), set(md.items()))
