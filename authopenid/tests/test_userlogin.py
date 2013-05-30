from __future__ import absolute_import

from StringIO import StringIO
import sys
from urlparse import urlparse

if sys.version_info >= (2, 7):
    import unittest
else:
    import unittest2 as unittest

from trac.test import EnvironmentStub
from trac.web.api import Request
from trac.web.session import DetachedSession

class UserLoginIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.env = EnvironmentStub()
        #assert self.env.dburi == 'sqlite::memory:'
        self.create_user('someone')

    def tearDown(self):
        self.env.destroy_db()

    def create_user(self, username):
        ds = DetachedSession(self.env, username)
        ds.save()

    def get_user_login(self):
        from authopenid.userlogin import UserLogin
        return UserLogin(self.env)

    def test_login(self):
        ul = self.get_user_login()
        req = MockRequest()

        with self.assertRaises(Redirected):
            ul.login(req, 'someone')
        self.assertEqual(req.authname, 'someone')
        self.assertIn('trac_auth', req.outcookie)

    def test_login_explicit_redirect(self):
        ul = self.get_user_login()
        base_url = 'http://example.com/trac'
        req = MockRequest(base_url=base_url)

        referer = base_url + '/subpage'
        with self.assertRaises(Redirected) as raised:
            ul.login(req, 'someone', referer)
        self.assertEqual(raised.exception.url, referer)

    def test_logout(self):
        ul = self.get_user_login()
        req = MockRequest(authname='someone')

        with self.assertRaises(Redirected):
            ul.logout(req)
        self.assertEqual(req.outcookie['trac_auth'].value, '')
        self.assertLess(req.outcookie['trac_auth']['expires'], 0)

    def test_logout_anonymous(self):
        ul = self.get_user_login()
        req = MockRequest()

        with self.assertRaises(Redirected):
            ul.logout(req)
        self.assertNotIn('trac_auth', req.outcookie)

    def test_logout_explicit_redirect(self):
        ul = self.get_user_login()
        base_url = 'http://example.com/trac'
        req = MockRequest(base_url=base_url, authname='x')

        referer = base_url + '/subpage'
        with self.assertRaises(Redirected) as raised:
            ul.logout(req, referer)
        self.assertEqual(raised.exception.url, referer)

    def test_authenticate(self):
        ul = self.get_user_login()
        req = MockRequest()

        self.assertIs(ul.authenticate(req), None)

        with self.assertRaises(Redirected):
            ul.login(req, 'someone')

        req2 = MockRequest()
        req2.incookie = req.outcookie
        self.assertEqual(ul.authenticate(req2), 'someone')

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

    def mock_start_response(self, status, headers):
        self.mock_response = status, headers

    def redirect(self, url, permanent=False):
        raise Redirected(url, permanent)
