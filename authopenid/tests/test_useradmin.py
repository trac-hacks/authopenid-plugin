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

from authopenid.exceptions import UserExists

class TestBase(unittest.TestCase):
    def setUp(self):
        self.env = EnvironmentStub()
        assert self.env.dburi == 'sqlite::memory:'

    def tearDown(self):
        self.env.global_databasemanager.shutdown()

    def get_user_manager(self):
        from authopenid.useradmin import UserManager
        return UserManager(self.env)

class TestUserManager(TestBase):
    def user_exists(self, username):
        with self.env.db_query as db:
            (n,), = db("SELECT count(*) FROM session"
                       " WHERE authenticated=%s and sid=%s",
                       (1, username))
            assert n <= 1
            return n

    def assert_user_exists(self, username):
        self.assertTrue(self.user_exists(username),
                        "user %r does not exists" % username)

    def test_create_user(self):
        m = self.get_user_manager()
        m.create_user('JoeBloe')
        self.assert_user_exists('JoeBloe')

    def test_create_user_lowercases_username(self):
        self.env.config.set('trac', 'ignore_auth_case', True)
        m = self.get_user_manager()
        m.create_user('JoeBloe')
        self.assert_user_exists('joebloe')

    def test_create_user_attributes(self):
        m = self.get_user_manager()
        data = {'foo': 'bar'}
        m.create_user('JoeBlow', attributes=data)
        session = DetachedSession(self.env, 'JoeBlow')
        self.assertEqual(dict(session), data)

    def test_create_raises_userexists(self):
        m = self.get_user_manager()
        m.create_user('Joe')
        with self.assertRaises(UserExists):
            m.create_user('Joe')
        self.assert_user_exists('Joe')

    def test_get_username_returns_none(self):
        m = self.get_user_manager()
        self.assertIs(m.get_username('identifier'), None)

    def test_get_username(self):
        m = self.get_user_manager()
        identifier = 'abcdef'
        m.create_user('Fred', openid_identifier=identifier)
        self.assertEqual(m.get_username(identifier), 'Fred')


class UserLoginIntegrationTests(TestBase):
    def setUp(self):
        super(UserLoginIntegrationTests, self).setUp()
        self.get_user_manager().create_user('someone')

    def get_user_login(self):
        from authopenid.useradmin import UserLogin
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
