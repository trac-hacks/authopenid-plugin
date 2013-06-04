from __future__ import absolute_import

import sys

if sys.version_info >= (2, 7):
    import unittest
else:
    import unittest2 as unittest

from mock import Mock, patch, call
import webob

from trac.test import EnvironmentStub
from trac.web.api import Request
from trac.web.chrome import Chrome
from trac.web import chrome
from trac.web.session import DetachedSession

class UserLoginIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.env = EnvironmentStub(enable=[])
        #assert self.env.dburi == 'sqlite::memory:'
        self.create_user('someone')

    def tearDown(self):
        self.env.destroy_db()

    def create_user(self, username):
        ds = DetachedSession(self.env, username)
        ds['name'] = 'someone'          # ds.save() wont save unless empty ds
        ds.save()

    def get_user_login(self):
        from authopenid.userlogin import UserLogin
        return UserLogin(self.env)

    def make_request(self, **kwargs):
        req = MockRequest(**kwargs)
        Chrome(self.env).prepare_request(req)
        return req

    def test_login(self):
        ul = self.get_user_login()
        req = self.make_request()

        with self.assertRaises(Redirected):
            ul.login(req, 'someone')
        self.assertEqual(req.authname, 'someone')
        self.assertIn('trac_auth', req.outcookie)

    def test_login_explicit_redirect(self):
        ul = self.get_user_login()
        base_url = 'http://example.com/trac'
        req = self.make_request(base_url=base_url)

        referer = base_url + '/subpage'
        with self.assertRaises(Redirected) as raised:
            ul.login(req, 'someone', referer)
        self.assertEqual(raised.exception.url, referer)

    def test_login_saves_chrome_messages(self):
        ul = self.get_user_login()
        req = self.make_request()

        chrome.add_warning(req, "a warning")
        chrome.add_notice(req, "a notice")
        self.assertEqual(len(req.chrome['warnings']), 1)
        self.assertEqual(len(req.chrome['notices']), 1)

        with self.assertRaises(Redirected):
            ul.login(req, 'someone')

        self.assertEqual(len(req.chrome['warnings']), 0)
        self.assertEqual(len(req.chrome['notices']), 0)
        ds = DetachedSession(self.env, 'someone')
        self.assertEqual(dict(ds), {
            'name': 'someone',
            'chrome.warnings.0': 'a warning',
            'chrome.notices.0': 'a notice',
            })

    def test_login_does_not_save_chrome_message_for_missing_user(self):
        ul = self.get_user_login()
        req = self.make_request()
        chrome.add_notice(req, "a notice")
        with self.assertRaises(Redirected):
            ul.login(req, 'nonexistant user')
        self.assertEqual(len(req.chrome['notices']), 1)
        ds = DetachedSession(self.env, 'nonexistant user')
        self.assertEqual(dict(ds), {})

    def test_logout(self):
        ul = self.get_user_login()
        req = self.make_request(authname='someone')

        with self.assertRaises(Redirected):
            ul.logout(req)
        self.assertEqual(req.outcookie['trac_auth'].value, '')
        self.assertLess(req.outcookie['trac_auth']['expires'], 0)

    def test_logout_anonymous(self):
        ul = self.get_user_login()
        req = self.make_request()

        with self.assertRaises(Redirected):
            ul.logout(req)
        self.assertNotIn('trac_auth', req.outcookie)

    def test_logout_explicit_redirect(self):
        ul = self.get_user_login()
        base_url = 'http://example.com/trac'
        req = self.make_request(base_url=base_url, authname='x')

        referer = base_url + '/subpage'
        with self.assertRaises(Redirected) as raised:
            ul.logout(req, referer)
        self.assertEqual(raised.exception.url, referer)

    def test_get_active_navigation_item(self):
        ul = self.get_user_login()
        req = self.make_request()
        self.assertEquals(ul.get_active_navigation_item(req), 'openid/logout')

    def test_get_navigation_items(self):
        ul = self.get_user_login()
        req = self.make_request(authname='joe')
        navitems = dict(((cat, name), text)
                        for cat, name, text in ul.get_navigation_items(req))
        self.assertEquals(set(navitems), set([('metanav', 'openid/login'),
                                              ('metanav', 'openid/logout')]))
        self.assertEquals(navitems['metanav', 'openid/login'],
                          'logged in as joe')
        self.assertEquals(
            navitems['metanav', 'openid/logout'].attrib.get('href'),
            req.href.openid('logout'))

    def test_get_navigation_items_anonymous(self):
        ul = self.get_user_login()
        req = self.make_request(authname='anonymous')
        self.assertEquals(list(ul.get_navigation_items(req)), [])

    def test_match_request(self):
        ul = self.get_user_login()
        self.assertTrue(ul.match_request(
            self.make_request(path_info='/openid/logout')))
        self.assertFalse(ul.match_request(
            self.make_request(path_info='/openid/login')))

    def test_process_request(self):
        ul = self.get_user_login()
        req = self.make_request(path_info='/openid/logout')
        with patch.object(ul, 'logout') as logout:
            ul.process_request(req)
        self.assertEquals(logout.mock_calls, [call(req)])

    def test_authenticate(self):
        ul = self.get_user_login()
        req = self.make_request()

        self.assertIs(ul.authenticate(req), None)

        with self.assertRaises(Redirected):
            ul.login(req, 'someone')

        req2 = self.make_request()
        req2.incookie = req.outcookie
        self.assertEqual(ul.authenticate(req2), 'someone')

class Redirected(Exception):
    @property
    def url(self):
        return self.args[0]


class MockRequest(Request):
    def __init__(self, base_url='http://example.net/', authname='anonymous',
                 path_info=''):
        environ = webob.Request.blank(base_url).environ

        # Cleanup HTTP_HOST
        if environ['HTTP_HOST'].endswith(':80'):
            environ['HTTP_HOST'] = environ['HTTP_HOST'][:-3]

        environ['SCRIPT_NAME'] = environ.pop('PATH_INFO')
        environ['PATH_INFO'] = path_info

        start_response = Mock(name='start_response', spec=())
        Request.__init__(self, environ, start_response)
        self.authname = authname
        self.locale = None

    def redirect(self, url, permanent=False):
        raise Redirected(url, permanent)

    @property
    def start_response(self):
        return self._start_response
