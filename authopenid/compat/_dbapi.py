""" Helpers for running under older trac 0.12
"""
from __future__ import absolute_import

import trac.core
from trac.db.api import DatabaseManager
import trac.db.util

try:
    from trac.test import InMemoryDatabase
except ImportError:                     # pragma: no cover
    # trac > 0.12
    InMemoryDatabase = None


class DbContextManager(object):
    db = None

    def __init__(self, env):
        self.env = env
        self._transaction_local = DatabaseManager(env)._transaction_local

    def __enter__(self):
        db = self._transaction_local.db
        if not db:
            db = self.env.get_db_cnx()
            self._transaction_local.db = self.db = db
        return ConnectionWrapper(db, db.log, self.readonly)

    def __exit__(self, type_, value, tb):
        if self.db:
            self._transaction_local.db = None
            if not self.readonly:
                if type_ is None:
                    self.db.commit()
                else:
                    self.db.rollback()
            if not isinstance(self.db, InMemoryDatabase):
                # Closing the in-memory database (testing) makes
                # it unusable
                self.db.close()

    def execute(self, query, params=()):
        with self as db:
            return db.execute(query, params)

    __call__ = execute

    def executemany(self, query, params=()):
        with self as db:
            return db.executemany(query, params)

class QueryContextManager(DbContextManager):
    readonly = True

class TransactionContextManager(DbContextManager):
    readonly = False

class ConnectionWrapper(trac.db.util.ConnectionWrapper):
    __slots__ = ('cnx', 'log', 'readonly')

    def __init__(self, cnx, log=None, readonly=False):
        self.cnx = cnx
        self.log = log or cnx.log
        self.readonly = readonly

    def __getattr__(self, name):
        if self.readonly and name in ('commit', 'rollback'):
            raise AttributeError
        return getattr(self.cnx, name)

    def execute(self, query, params=()):
        """Execute an SQL `query`

        The optional `params` is a tuple containing the parameter
        values expected by the query.

        If the query is a SELECT, return all the rows ("fetchall").
        When more control is needed, use `cursor()`.
        """
        dql = self.check_select(query)
        cursor = self.cnx.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall() if dql else None
        cursor.close()
        return rows

    __call__ = execute

    def executemany(self, query, params=()):
        """Execute an SQL `query`, on a sequence of tuples ("executemany").

        The optional `params` is a sequence of tuples containing the
        parameter values expected by the query.

        If the query is a SELECT, return all the rows ("fetchall").
        When more control is needed, use `cursor()`.
        """
        dql = self.check_select(query)
        cursor = self.cnx.cursor()
        cursor.executemany(query, params)
        rows = cursor.fetchall() if dql else None
        cursor.close()
        return rows

    def check_select(self, query):
        """Verify if the query is compatible according to the readonly
        nature of the wrapped Connection.

        :return: `True` if this is a SELECT
        :raise: `ValueError` if this is not a SELECT and the wrapped
        Connection is read-only.
        """
        dql = query.lstrip().startswith('SELECT')
        if self.readonly and not dql:
            raise ValueError(
                "a 'readonly' connection can only do a SELECT")
        return dql

class EnvironmentModernizer(object):
    __slots__ = ['env']

    def __init__(self, env):
        object.__setattr__(self, 'env', env)

    def __getattr__(self, attr):
        return getattr(self.env, attr)

    def __setattr__(self, attr, value):
        # There's no real reason not to support setting attributes,
        # but at present, there doesn't seem to be a need.
        raise AttributeError('Attributes can not be set through proxy')

    def __getitem__(self, key):
        return self.env[key]

    def __contains__(self, key):
        return key in self.env

    @property
    def db_transaction(self):
        return TransactionContextManager(self)

    @property
    def db_query(self):
        return QueryContextManager(self)


def modernize_env(env):                 # pragma: no cover
    if not hasattr(env, 'db_query'):
        return EnvironmentModernizer(env)
    return env

class ModernizedComponent(trac.core.Component):
    abstract = True

    def __init__(self):
        self.env = modernize_env(self.env)
