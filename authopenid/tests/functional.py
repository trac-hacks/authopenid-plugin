""" Functional tests

.. NOTE:: This file is named ``functional.py`` rather than
   ``test_functional.py`` so that ``unit2 discover`` (and similar)
   won't run it by default.  (It is slow.)

   To run the functional test you can do something like::

       unit2 discover -p functional.py

   or, to run all tests::

       unit2 authopenid.tests.suite

"""
from __future__ import absolute_import

import atexit
import os
import re
import shutil
import sys
from pkg_resources import resource_filename
from tempfile import mkdtemp
import unittest
if not hasattr(unittest.TestCase, 'assertIn'):
    import unittest2 as unittest

from trac.env import Environment
from trac.web.main import dispatch_request
from trac.wiki.admin import WikiAdmin

from webtest import TestApp
import webtest.lint

def print_log_on_failure(wrapped):
    def wrapper(self):
        try:
            wrapped(self)
        except AssertionError:
            if os.path.isfile(self.log_file):
                sys.stdout.writelines(file(self.log_file))
            raise
    try:
        wrapper.__name__ = wrapped.__name__
    except:
        pass
    return wrapper

class FunctionalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = TempEnvironment()

    def setUp(self):
        self.truncate_log_file()
        the_app = make_wsgi_app(self.env)
        the_app = webtest.lint.middleware(the_app)
        self.app = TestApp(the_app)

    def truncate_log_file(self):
        try:
            with file(self.log_file, 'w') as f:
                f.truncate(0)
        except IOError:
            pass

    @property
    def log_file(self):
        log_file = self.env.config.get('logging', 'log_file')
        if not os.path.isabs(log_file):
            log_file = os.path.join(self.env.get_log_dir(), log_file)
        return log_file


    @print_log_on_failure
    def test_homepage(self):
        homepage = self.app.get('/')
        self.assertEqual(homepage.status_int, 200)
        self.assertRegexpMatches(homepage.normal_body,
                                 r'Welcome to Trac\b.*Enjoy!')
        self.assertTrue(homepage.html('a', href=re.compile(r'\A/openid/login')))

    def do_login(self, openid_identifier):
        login = self.app.get('/openid/login')
        self.assertEqual(login.status_int, 200)

        form = next(f for f in login.forms.values()
                    if 'openid_identifier' in f.fields)
        form['openid_identifier'] = openid_identifier
        return form.submit()

    @print_log_on_failure
    def test_login_empty_identifier(self):
        resp = self.do_login('')
        self.assertEqual(resp.status_int, 200)
        self.assertRegexpMatches(resp.text, r'(?i)Enter an OpenID Identifier')

    @print_log_on_failure
    def test_login(self):
        resp = self.do_login('https://www.google.com/accounts/o8/id')
        self.assertEqual(resp.status_int, 200)
        self.assertEqual(resp.form.action,
                         'https://www.google.com/accounts/o8/ud')

class TempEnvironment(Environment):

    dburi = 'sqlite:db/trac.db'
    project_name = 'TestEnvironment'

    def __init__(self):
        self._rmtree = shutil.rmtree
        Environment.__init__(self, mkdtemp(), create=True, options=[
            ('project', 'name', self.project_name),
            ('trac', 'database', self.dburi),

            ('logging', 'log_type', 'file'),
            ('logging', 'log_file', 'log'),
            ('logging', 'log_level', 'DEBUG'),

            # FIXME: make this configurable?
            ('components', 'trac.web.auth.*', 'disabled'),
            ('components', 'authopenid.*', 'enabled'),
            ])

        atexit.register(self.close)
        assert not self.needs_upgrade(), "Environment needs upgrade"

        self._setup()

    def _setup(self):
        # Install default wiki page
        pages = resource_filename('trac.wiki', 'default-pages')
        for title in ['WikiStart']:
            WikiAdmin(self).import_page(os.path.join(pages, title), title)

        assert not self.needs_upgrade(), "Environment needs upgrade"

    def close(self):
        if self._rmtree:
            self._rmtree(self.path)
            self._rmtree = None

def make_wsgi_app(env):
    def app(environ, start_response):
        environ['trac.env_path'] = env.path
        return dispatch_request(environ, start_response)
    return app

if __name__ == '__main__':
    unittest.main()
