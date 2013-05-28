"""
"""
from __future__ import absolute_import

from collections import MutableMapping
from urlparse import urljoin, urlparse, urlunparse

from trac.core import TracError
from trac.db.api import DatabaseManager

from authopenid.compat import TransactionContextManager

def sanitize_referer(referer, base_url):
    """ Ensure that ``referer`` is 'under' ``base_url``.

    This interprets ``referer`` relative to ``base_url``.  Any anchor or
    query is removed.

    Returns a normalized absolute version of ``referer`` if it refers
    to a URL which is or is 'under' ``base_url``; otherwise returns ``None``.

    """
    if referer is None:
        return None
    abs_referer = urljoin(base_url, referer)
    base = urlparse(base_url)
    assert base.scheme and base.netloc

    # make absolute
    ref = urlparse(abs_referer)
    if (ref.scheme, ref.netloc) != (base.scheme, base.netloc):
        return None


    split_path = split_path_info(ref.path)
    if ref.path.endswith('/'):
        split_path.append('')
    base_path = split_path_info(base.path)

    if split_path[:len(base_path)] != base_path:
        return None
    return urlunparse((ref.scheme, ref.netloc, '/'.join(split_path),
                       None, None, None))

def split_path_info(path):
    assert path.startswith('/')
    clean = []
    for segment in path.split('/'):
        if segment and segment != '.':
            if segment == '..':
                if clean:
                    del clean[-1]
            else:
                clean.append(segment)
    return [''] + clean



_LIST_TABLES_SQL = {
    'sqlite':
    """SELECT name FROM sqlite_master
       WHERE type='table' AND NOT name='sqlite_sequence'""",

    'postgres':
    """SELECT tablename FROM pg_tables
       WHERE schemaname = ANY (current_schemas(false))""",

    'mysql': "SHOW TABLES",
    }

def get_db_scheme(env):
    dburi = DatabaseManager(env).connection_uri
    scheme = dburi.split(':', 1)[0]
    return scheme

def list_tables(env):
    # Based on code from TracMigratePlugin by Jun Omae
    scheme = get_db_scheme(env)
    try:
        sql = _LIST_TABLES_SQL[scheme]
    except KeyError:
        raise TracError("Unsupported database scheme '%s'" % scheme)

    with TransactionContextManager(env) as db:
        return set(row[0] for row in db(sql))

def table_exists(env, tablename):
    return tablename in list_tables(env)

class MultiDict(MutableMapping):
    """ A dictionary with multiple values per key

    This behaves like an ordinary dictionary except that is can store
    multiple values for a single key.

    Multiple values can only be created by using the ``add`` method,
    (or by ``__init__`` when given an iterable as the only argument.)
    The multiple values can be accessed using the ``getall``method.

    (The ``__setitem__`` method replaces any existing values; if there
    are multiple values ``__getitem__`` returns only the first.)

    """
    def __init__(self, *args, **kwargs):
        self.data = dict()
        if args:
            values, = args
            if callable(getattr(values, 'items', None)):
                values = values.items()
            for k, v in values:
                self.add(k, v)
        self.update(kwargs)

    def add(self, key, value):
        self.data.setdefault(key, []).append(value)

    def getall(self, key, default=()):
        try:
            return tuple(self.data[key])
        except KeyError:
            return default

    def __getitem__(self, key):
        return self.data[key][0]

    def __iter__(self):
        return iter(self.data)

    def __len__(self):
        return len(self.data)

    def __setitem__(self, key, value):
        self.data[key] = [value]

    def __delitem__(self, key):
        del self.data[key]

    def __repr__(self):
        init = tuple((k, v)
                     for k, data in self.data.items()
                     for v in data)
        return "%s(%r)" % (self.__class__.__name__, init)
