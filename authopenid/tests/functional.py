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
import webtest.lint
import webob

import openid
from openid.server.server import Server as openid_Server
from openid.store.memstore import MemoryStore
from openid.extensions import ax

from trac.env import Environment
from trac.web.main import dispatch_request
from trac.wiki.admin import WikiAdmin

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
        cls.env = TempEnvironment()

        # Start up test OP server
        cls.op = TestOpenIDServer()
        cls.op_server = StopableWSGIServer.create(cls.op.wsgi_app)
        cls.op.base_url = cls.op_server.application_url
        cls.op_server.wait()

    @classmethod
    def tearDownClass(cls):
        cls.op_server.shutdown()

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

    @print_log_on_failure
    def test_homepage(self):
        homepage = self.app.get('/')
        self.assertEqual(homepage.status_int, 200)
        self.assertRegexpMatches(homepage.normal_body,
                                 r'Welcome to Trac\b.*Enjoy!')
        self.assert_logged_out(homepage)

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
        self.assert_logged_out(resp)

    @print_log_on_failure
    def test_discovery_failure(self):
        resp = self.do_login('http://does.not.exist/')
        self.assertEqual(resp.status_int, 200)
        self.assertIn('Error fetching XRDS document', resp.normal_body)
        self.assertTrue(resp.html.find('input', {'name':'openid_identifier'}))
        self.assert_logged_out(resp)

    @print_log_on_failure
    def test_login_logout(self):
        identifier = self.op.get_identifier('someuser')
        resp = self.do_login(identifier)
        self.assertEqual(resp.status_int, 200)
        self.assertEqual(resp.form.action, self.op.op_endpoint)
        self.assertEqual(resp.form.method, 'post')

        # Do real submission to our test OP
        resp = submit_form(resp.form)
        self.assertEqual(resp.status_code, 302)
        location = resp.headers['location']
        self.assertEqual(urlparse(location).path, '/openid/response')
        resp = self.app.get(location).maybe_follow()

        # Check that we're logged in
        self.assert_logged_in(resp)
        # Check for the chrome notice
        message = resp.html.find('div', {'class': 'system-message'})
        self.assertRegexpMatches(str(message),
                                 r'Your new username is .*\bsomeuser\b')

        # Log out
        resp = resp.click(href='/logout').maybe_follow()
        self.assert_logged_out(resp)

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
            return request.anser(False) # not authenticated

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


if __name__ == '__main__':
    unittest.main()
