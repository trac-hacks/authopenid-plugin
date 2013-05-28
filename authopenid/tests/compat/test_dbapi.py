from __future__ import absolute_import

import unittest
if not hasattr(unittest, 'skipIf'):
    import unittest2 as unittest

import trac.db.api
from trac.test import EnvironmentStub

from mock import call, Mock, patch, sentinel

is_modern_trac = hasattr(trac.db.api, 'QueryContextManager')
skipIfModernTrac = unittest.skipIf(is_modern_trac, "running under trac >= 1.0")

class CnxTestBase(unittest.TestCase):
    def setUp(self):
        self.env = EnvironmentStub()
        #assert self.env.dburi == 'sqlite::memory:'
        self.env.get_db_cnx = Mock(name='get_db_cnx')
        self.cnx = self.env.get_db_cnx.return_value

    def tearDown(self):
        self.env.destroy_db()

class DbContextManagerTests(object):
    def test_nested_does_not_commit(self):
        with self.make_one() as outer_db:
            with self.make_one() as inner_db:
                pass
            self.assertEquals(self.cnx.mock_calls, [])

    def test_nested_does_not_rollback(self):
        with self.make_one() as outer_db:
            try:
                with self.make_one() as inner_db:
                    raise RuntimeError()
            except RuntimeError:
                pass
            self.assertEquals(self.cnx.mock_calls, [])

    def test_execute(self):
        with patch('authopenid.compat._dbapi.ConnectionWrapper') \
                 as ConnectionWrapper:
            self.make_one().execute("STATEMENT")

        self.assertEquals(ConnectionWrapper().mock_calls, [
            call.execute("STATEMENT", ())
            ])
        self.assertIn(call.close(), self.cnx.mock_calls)

    def test_executemany(self):
        with patch('authopenid.compat._dbapi.ConnectionWrapper') \
                 as ConnectionWrapper:
            self.make_one().executemany("STATEMENT", [('args',)])

        self.assertEquals(ConnectionWrapper().mock_calls, [
            call.executemany("STATEMENT", [('args',)])
            ])
        self.assertIn(call.close(), self.cnx.mock_calls)

@skipIfModernTrac
class TestTransactionContextManager(CnxTestBase, DbContextManagerTests):
    def make_one(self):
        from authopenid.compat._dbapi import TransactionContextManager
        return TransactionContextManager(self.env)

    def test_wrapper_is_writeable(self):
        with patch('authopenid.compat._dbapi.ConnectionWrapper') \
                 as ConnectionWrapper:
            with self.make_one() as db:
                pass
        self.assertEquals(ConnectionWrapper.mock_calls, [
            call(self.cnx, self.cnx.log, False)
            ])

    def test_commit(self):
        with self.make_one() as db:
            pass
        self.assertEquals(self.cnx.mock_calls, [call.commit(), call.close()])

    def test_rollback(self):
        try:
            with self.make_one() as db:
                raise RuntimeError()
        except RuntimeError:
            pass
        self.assertEquals(self.cnx.mock_calls, [call.rollback(), call.close()])

@skipIfModernTrac
class TestQueryContextManager(CnxTestBase, DbContextManagerTests):
    def make_one(self):
        from authopenid.compat._dbapi import QueryContextManager
        return QueryContextManager(self.env)

    def test_wrapper_is_readonly(self):
        with patch('authopenid.compat._dbapi.ConnectionWrapper') \
                 as ConnectionWrapper:
            with self.make_one() as db:
                pass
        self.assertEquals(ConnectionWrapper.mock_calls, [
            call(self.cnx, self.cnx.log, True)
            ])

    def test_no_commit(self):
        with self.make_one() as db:
            pass
        self.assertEquals(self.cnx.mock_calls, [call.close()])

    def test_no_rollback(self):
        try:
            with self.make_one() as db:
                raise RuntimeError()
        except RuntimeError:
            pass
        self.assertEquals(self.cnx.mock_calls, [call.close()])

class TestConnectionWrapper(unittest.TestCase):
    def setUp(self):
        self.cnx = Mock(name='cnx')

    def make_one(self, readonly=False):
        from authopenid.compat._dbapi import ConnectionWrapper
        return ConnectionWrapper(self.cnx, readonly=readonly)

    def test_commit(self):
        db = self.make_one()
        db.commit()
        self.assertEquals(self.cnx.mock_calls, [call.commit()])

    def test_readonly_can_not_commit_or_rollback(self):
        db = self.make_one(readonly=True)
        with self.assertRaises(AttributeError):
            db.commit()
        with self.assertRaises(AttributeError):
            db.rollback()

    def test_execute_select(self):
        db = self.make_one()
        db.execute('SELECT * FROM system')
        self.assertEquals(self.cnx.mock_calls, [
            call.cursor(),
            call.cursor().execute('SELECT * FROM system', ()),
            call.cursor().fetchall(),
            call.cursor().close(),
            ])

    def test_executemany(self):
        db = self.make_one()
        db.executemany('NOT SELECT', [('args',)])
        self.assertEquals(self.cnx.mock_calls, [
            call.cursor(),
            call.cursor().executemany('NOT SELECT', [('args',)]),
            call.cursor().close(),
            ])

    def test_readonly_can_only_select(self):
        db = self.make_one(readonly=True)
        with self.assertRaises(ValueError):
            db.execute("NOT SELECT")
        db.execute("SELECT")
        self.assertIn(call.cursor().execute('SELECT', ()),
                      self.cnx.mock_calls)

class TestEnvironmentModernizer(CnxTestBase):
    def modernize_env(self, env):
        from authopenid.compat._dbapi import EnvironmentModernizer
        return EnvironmentModernizer(env)

    def test_db_transaction(self):
        env = self.modernize_env(self.env)
        with patch('authopenid.compat._dbapi.TransactionContextManager') \
                 as TransactionContextManager:
            self.assertEquals(env.db_transaction,
                              TransactionContextManager.return_value)

    def test_db_query(self):
        env = self.modernize_env(self.env)
        with patch('authopenid.compat._dbapi.QueryContextManager') \
                 as QueryContextManager:
            self.assertEquals(env.db_query, QueryContextManager.return_value)

    def test_attributes_readonly(self):
        env = self.modernize_env(self.env)
        with self.assertRaises(AttributeError):
            env.path = '/tmp'

class TestModernizedComponent(CnxTestBase):
    def test(self):
        from authopenid.compat._dbapi import ModernizedComponent

        class MyComponent(ModernizedComponent):
            pass

        comp = MyComponent(self.env)
        self.assertTrue(hasattr(comp.env, 'db_query'))
