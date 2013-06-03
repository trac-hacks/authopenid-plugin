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
from httplib import HTTPConnection
import os
import re
import shutil
import sys
from pkg_resources import resource_filename
from tempfile import mkdtemp
from urllib import urlencode
from urlparse import urlparse
import warnings
import unittest
if not hasattr(unittest.TestCase, 'assertIn'):
    import unittest2 as unittest

from webtest import TestApp
from webtest.http import StopableWSGIServer
from webtest.response import TestResponse
import webob

import openid
from openid.server.server import Server as openid_Server
from openid.store.memstore import MemoryStore
from openid.extensions import ax

from trac.config import Configuration
from trac.env import Environment
from trac.web.main import dispatch_request
from trac.web.session import DetachedSession
from trac.wiki.admin import WikiAdmin

from authopenid.compat import modernize_env

if openid.version_info <= (2, 2, 5):
    # Warnings expected from python-openid 2.2.5
    # NB: 2.2.5 reports itself as 2.2.1
    warnings.filterwarnings(
        'ignore', 'cgi.parse_qsl is deprecated',
        category=PendingDeprecationWarning,
        module='openid.consumer.consumer', lineno=854)

    # here python-openid issues a deprecation warning to itself
    warnings.filterwarnings(
        'ignore',
        'The "namespace" attribute of CheckIDRequest objects is deprecated',
        category=DeprecationWarning,
        module='openid.server.server', lineno=980)

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
        # Start up test OP server
        cls.op = TestOpenIDServer()
        cls.op_server = StopableWSGIServer.create(cls.op.wsgi_app)
        cls.op.base_url = cls.op_server.application_url
        cls.op_server.wait()

    @classmethod
    def tearDownClass(cls):
        cls.op_server.shutdown()

    def setUp(self):
        self.env = TempEnvironment.singleton()

        self.truncate_log_file()
        the_app = make_wsgi_app(self.env)
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

    def create_user(self, username, **kwargs):
        ds = DetachedSession(self.env, username)
        ds.update(kwargs)
        assert ds, "ds.save() won't save unless there are some user attributes"
        ds.save()

    def assert_logged_in(self, resp):
        self.assertTrue(resp.html('a', href=re.compile(r'/logout\b')),
                        "Not logged in (no logout link found)")
        self.assertFalse(resp.html('a', href=re.compile(r'\A/openid/login')),
                         "Not logged in (login link found)")


    def assert_logged_out(self, resp):
        self.assertTrue(resp.html('a', href=re.compile(r'\A/openid/login')),
                        "Not logged out (no login link found)")
        self.assertFalse(resp.html('a', href=re.compile(r'/logout\b')),
                         "Not logged out (logout link found)")

    def assert_chrome_message(self, resp, text=None, type_=None):
        if text is None:
            text = re.compile('.')
        elif not hasattr(text, 'search'):
            text = re.compile(text or '.')

        for message in resp.html('div', 'system-message'):
            if type_ is None \
                   or type_ in message['class'] \
                   or message['id'] == type_:
                if text.search(''.join(message.strings)):
                    return
        self.fail("No chrome %s matching %r"
                  % (type_ or 'message', text.pattern))

    def assert_notice(self, resp, text=None):
        self.assert_chrome_message(resp, text, 'notice')

    def assert_warning(self, resp, text=None):
        self.assert_chrome_message(resp, text, 'warning')

    def submit_authentication_form(self, resp, openid_identifier):
        """ Find the openid authentication form in resp, and submit it

        Follow any resulting redirects (including the auto-submit
        form, if any)
        """
        self.assertEquals(resp.status_int, 200)
        for form in set(resp.forms.values()):
            if 'openid_identifier' in form.fields:
                break
        else:
            self.fail("Can not find login form")

        form['openid_identifier'] = openid_identifier
        resp = form.submit()

        if resp.status_int == 200 \
               and resp.html.find('input', {'name': 'openid.mode'}):
            # Handle auto-submit form
            self.assertEqual(resp.form.action, self.op.op_endpoint)
            # Do real submission to our test OP
            resp = submit_form(resp.form)
            self.assertEqual(resp.status_code, 302)
            location = resp.headers['location']
            self.assertTrue(location.startswith(self.env.base_url))
            # Process the indirect response
            return self.app.get(location).maybe_follow()
        # XXX: Should handle 302 redirect to OP?

        while resp.status_int == 302:
            resp = resp.follow()
        self.assertEquals(resp.status_int, 200)
        return resp


    @print_log_on_failure
    def test_homepage(self):
        homepage = self.app.get('/')
        self.assertEqual(homepage.status_int, 200)
        self.assertRegexpMatches(homepage.normal_body,
                                 r'Welcome to Trac\b.*Enjoy!')
        self.assert_logged_out(homepage)

    @print_log_on_failure
    def test_login_empty_identifier(self):
        resp = self.app.get('/').click(href='/openid/login')
        resp = self.submit_authentication_form(resp, '')
        self.assertEquals(resp.request.path_info, '/openid/login')
        self.assertRegexpMatches(resp.text, r'(?i)Enter an OpenID Identifier')
        self.assert_logged_out(resp)

    @print_log_on_failure
    def test_discovery_failure(self):
        resp = self.app.get('/').click(href='/openid/login')
        resp = self.submit_authentication_form(resp, 'http://does.not.exist/')
        self.assertIn('Error fetching XRDS document', resp.normal_body)
        self.assertTrue(resp.html.find('input', {'name':'openid_identifier'}))
        self.assert_logged_out(resp)

    @print_log_on_failure
    def test_login_cancelled(self):
        identifier = self.op.get_identifier('__cancelled__')
        resp = self.app.get('/').click(href='/openid/login')
        resp = self.submit_authentication_form(resp, identifier)
        self.assert_logged_out(resp)
        self.assert_warning(resp, r'Cancelled')

    @print_log_on_failure
    def test_login_logout(self):
        identifier = self.op.get_identifier('someuser')
        resp = self.app.get('/').click(href='/openid/login')
        resp = self.submit_authentication_form(resp, identifier)
        self.assert_logged_in(resp)
        self.assert_notice(resp, r'Your new username is .*\bsomeuser\b')
        self.assertEquals(resp.request.path_info, '/')

        resp = resp.click(href='/logout').maybe_follow()
        self.assert_logged_out(resp)

    @print_log_on_failure
    def test_login_unauthorized(self):
        identifier = self.op.get_identifier('unauthorized')
        self.env.config.set('openid', 'black_list', identifier)
        self.env.config.save()

        resp = self.app.get('/').click(href='/openid/login')
        resp = self.submit_authentication_form(resp, identifier)
        self.assert_logged_out(resp)
        self.assert_warning(resp, r'(?i)Not\s*Authorized')
        self.assertEqual(resp.request.path_info, '/openid/login')

    @print_log_on_failure
    def test_interactive_registration(self):
        self.env.config.set('openid', 'registration_module',
                            'OpenIDInteractiveRegistrationModule')
        self.env.config.save()
        identifier = self.op.get_identifier('someuser')
        resp = self.app.get('/').click(href='/openid/login')
        resp = self.submit_authentication_form(resp, identifier)

        self.assert_logged_out(resp)
        regform = resp.forms['register']
        regform['username'] = 'New Username'

        resp = regform.submit().maybe_follow()
        self.assert_logged_in(resp)
        self.assert_notice(resp, r'Your new username is .*\bNew Username\b')
        self.assertEquals(resp.request.path_info, '/')

    @print_log_on_failure
    def test_prefs(self):
        self.env.config.set('components', 'trac.web.auth.*', 'enabled')
        self.env.config.save()

        self.create_user('joe', name='Joe')
        resp = self.app.get('/login', extra_environ={'REMOTE_USER': 'joe'})
        resp = resp.follow()
        self.assert_logged_in(resp)

        resp = resp.click('Preferences')
        resp = resp.click('OpenID')

        # Abstract this
        new_identifier = self.op.get_identifier('joey')
        resp = self.submit_authentication_form(resp, new_identifier)
        self.assertEqual(resp.request.path_info, '/prefs/openid')
        self.assertTrue(resp.html('input', {'name': 'association',
                                            'value': new_identifier}))
        self.assertTrue(resp.html('code', text=new_identifier))

        # Delete the association
        form = next(form for form in resp.forms.values()
                    if 'association' in form.fields
                    and form['association'].value == new_identifier)
        resp = form.submit().maybe_follow()
        self.assertEqual(resp.request.path_info, '/prefs/openid')
        self.assertFalse(resp.html('input', {'name': 'association',
                                             'value': new_identifier}))

def make_wsgi_app(trac_env):
    def app(environ, start_response):
        environ['trac.env_path'] = trac_env.path
        return dispatch_request(environ, start_response)
    return app

def submit_form(form):
    """ This does a real HTTP submission of the form.

    (form.submit() does a fake submit, passing the request to the TestApp)
    """
    action = urlparse(form.action)
    http = HTTPConnection(action.netloc, strict=True)
    http.request('POST', action.path,
                 urlencode(form.submit_fields()),
                 {'Content-Type': 'application/x-www-form-urlencoded'})
    resp = http.getresponse()
    return TestResponse(body=resp.read(),
                        status_code=resp.status,
                        headerlist=resp.getheaders())


class TempEnvironment(Environment):
    """ Create a temporary (but real) trac environment.

    """
    dburi = 'sqlite:db/trac.db'
    project_name = 'TestEnvironment'

    _singleton = None

    @classmethod
    def singleton(cls, options=(), **kwargs):
        if cls._singleton is None:
            cls._singleton = cls(**kwargs)
            config = cls._singleton.config
            shutil.copy(config.filename, config.filename + '.orig')
        else:
            config = cls._singleton.config
            shutil.copy(config.filename + '.orig', config.filename)

        cls._singleton.config = Configuration(config.filename)
        for section, key, value in options:
            config.set(section, key, value)
        config.save()

        env = modernize_env(cls._singleton)
        with env.db_transaction as db:
            db("DELETE FROM session")
            db("DELETE FROM session_attribute")

        return cls._singleton

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

class TestOpenIDServer(object):
    """ A simple OpenID server

    This is a basic OpenID server which we use authenticate against
    in the functional tests.

    """
    def __init__(self):
        self.store = MemoryStore()
        self.base_url = 'https://example.com/'

    @property
    def op_endpoint(self):
        return self.base_url + 'op'

    def get_identifier(self, username):
        """ Get OP-local identifier for user """
        return self.base_url + username

    def wsgi_app(self, environ, start_response):
        req = webob.Request(environ)
        try:
            if req.path_info == '/op':
                res = self._handle_openid_request(req)
            else:
                res = self._handle_discovery(req)
        except Exception as exc:
            print >>sys.stderr, "OpenID server: %s" % exc
            raise
        return res(environ, start_response)


    def _handle_openid_request(self, req):
        server = openid_Server(self.store, self.op_endpoint)
        request = server.decodeRequest(req.params)
        if request.mode in ['checkid_immediate', 'checkid_setup']:
            response = self._do_checkid(request)
        else:
            response = server.handleRequest(request)
        r = server.encodeResponse(response)
        # r.headers has unicode values for some reason (even though it all
        # looks urlencoded)
        headers = [(str(k), str(v)) for k, v in r.headers.items()]
        return webob.Response(
            status_code=r.code, headerlist=headers, body=r.body)

    def _do_checkid(self, request):
        identity = request.identity
        id_path = urlparse(identity).path
        if identity.startswith(self.base_url) and id_path:
            assert id_path.startswith('/')
            username = id_path[1:]
        else:
            username = None

        if username in ('__cancelled__', None):
            return request.answer(False) # not authenticated

        response = request.answer(True)
        ax_req = ax.FetchRequest.fromOpenIDRequest(request)
        if ax_req:
            response.addExtension(self._get_ax_response(ax_req, username))
        return response

    def _get_ax_response(self, ax_req, username):
        data = {
            'http://axschema.org/namePerson/friendly': [username], # nickname
            }
        ax_resp = ax.FetchResponse(ax_req)
        for type_uri, values in data.items():
            if type_uri in ax_req:
                ax_resp.setValues(type_uri, values)
        return ax_resp

    def _handle_discovery(self, request):
        elems = [
            '<Type>http://openid.net/srv/ax/1.0</Type>',
            '<URI>%s</URI>' % self.op_endpoint,
            ]
        if request.path_info:
            # claimed identifier discovery
            assert request.path_info.startswith('/')
            username = request.path_info[1:]
            identifier = self.get_identifier(username)
            elems.insert(
                0, '<Type>http://specs.openid.net/auth/2.0/signon</Type>')
            elems.append(u'<LocalID>%s</LocalID>' % identifier)
        else:
            # OP identifier (server-select) discovery
            elems.insert(
                0, '<Type>http://specs.openid.net/auth/2.0/server</Type>')

        body = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)">',
            '<XRD>',
            '<Service priority="0">',
            ] + elems + [
            '</Service>',
            '</XRD>',
            '</xrds:XRDS>',
            ]

        return webob.Response('\n'.join(body),
                              content_type='application/xrds+xml',
                              charset='utf-8')

def suite():
    loader = unittest.defaultTestLoader
    return loader.loadTestsFromTestCase(FunctionalTests)

if __name__ == '__main__':
    unittest.main()
