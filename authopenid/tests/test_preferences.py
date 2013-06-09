# -*- coding: utf-8 -*-
from __future__ import absolute_import

from urllib import urlencode
import unittest
if not hasattr(unittest, 'skipIf'):
    import unittest2 as unittest

from mock import Mock, patch, call, ANY, DEFAULT
import webob

from openid.consumer.discover import DiscoveryFailure

from genshi.core import escape

from trac.test import EnvironmentStub
from trac.web.api import Request
from trac.web.chrome import Chrome

from authopenid.api import (
    AuthenticationFailed,
    OpenIDIdentifierInUse,
    UserNotFound,
    )

class TestOpenIDPreferencePanel(unittest.TestCase):
    def setUp(self):
        self.env = EnvironmentStub()
        #assert self.env.dburi == 'sqlite::memory:'
        self.env.config.set('openid', 'fancy_selector', None)

    def tearDown(self):
        self.env.destroy_db()

    def get_component(self):
        from authopenid.preferences import OpenIDPreferencePanel
        return OpenIDPreferencePanel(self.env)

    def make_request(self, *args, **kwargs):
        req = MockRequest(*args, **kwargs)
        Chrome(self.env).prepare_request(req)
        return req

    def assert_render_preference_panel_renders_panel(self, req, panel='openid'):
        prefs = self.get_component()
        with patch.object(prefs.__class__, 'identifier_store') \
                 as identifier_store:
            tmpl, data = prefs.render_preference_panel(req, panel)
        self.assertEquals(tmpl, 'openid_preferences.html')

    def test_get_preference_panels(self):
        req = self.make_request(authname='joe')
        prefs = self.get_component()
        self.assertEquals(list(prefs.get_preference_panels(req)),
                          [('openid', 'OpenID')])

    def test_get_preference_panels_anonymous(self):
        req = self.make_request(authname='anonymous')
        prefs = self.get_component()
        self.assertEquals(list(prefs.get_preference_panels(req)), [])

    def test_render_preference_panel(self):
        req = self.make_request(authname='joe')
        self.assert_render_preference_panel_renders_panel(req)
        self.assertFalse(req.chrome['warnings'])

    def test_render_preference_panel_with_fancy_selector(self):
        from authopenid.authopenid import AuthOpenIdPlugin
        req = self.make_request(authname='joe')
        prefs = self.get_component()
        with patch.object(prefs.__class__, 'identifier_store') \
                 as identifier_store:
            with patch.object(AuthOpenIdPlugin, 'fancy_selector') \
                     as fancy_selector:
                tmpl, data = prefs.render_preference_panel(req, 'openid')
        self.assertIs(data['selector'],
                      fancy_selector.get_template_data.return_value)

    def test_render_preference_panel_POST_action_associate(self):
        req = self.make_request(authname='joe', method='POST',
                                args={'action': 'associate',
                                      'openid_identifier': '=id'})
        prefs = self.get_component()
        with patch.object(prefs.__class__, 'openid_consumer') \
                 as openid_consumer:
            rv = prefs.render_preference_panel(req, 'openid')
        self.assertIs(rv, openid_consumer.begin.return_value)
        self.assertEquals(openid_consumer.mock_calls, [
            call.begin(req, '=id', req.abs_href.openid('associate')),
            ])

    def test_render_preference_panel_POST_action_associate_no_id(self):
        req = self.make_request(authname='joe', method='POST',
                                args={'action': 'associate'})
        self.assert_render_preference_panel_renders_panel(req)
        self.assertIn("Enter an OpenID identifier", req.chrome['warnings'])

    def test_render_preference_panel_POST_action_associate_failure(self):
        req = self.make_request(authname='joe', method='POST',
                                args={'action': 'associate',
                                      'openid_identifier': '=id'})
        prefs = self.get_component()
        with patch.object(prefs.__class__, 'openid_consumer') \
                 as openid_consumer:
            openid_consumer.begin.side_effect = DiscoveryFailure("test", 404)
            self.assert_render_preference_panel_renders_panel(req)
        self.assertIn("Discovery failure: test", req.chrome['warnings'])

    def test_render_preference_panel_POST_not_logged_in(self):
        req = self.make_request(authname='anonymous', method='POST',
                                args={'action': 'associate',
                                      'openid_identifier': '=id'})
        self.assert_render_preference_panel_renders_panel(req)
        self.assertIn("Not logged in", req.chrome['warnings'][0])

    def test_render_preference_panel_POST_unknown_action(self):
        req = self.make_request(authname='joe',
                                method='POST', args={'action': 'bogus'})
        self.assert_render_preference_panel_renders_panel(req)

    def test_render_preference_panel_POST_delete_associations(self):
        req = self.make_request(authname='joe', method='POST',
                                args=[('action', 'delete_associations'),
                                      ('association', '=id')])
        prefs = self.get_component()
        with patch.object(prefs.__class__, 'identifier_store') \
                 as identifier_store:
            tmpl, data = prefs.render_preference_panel(req, 'openid')
        self.assertEquals(tmpl, "openid_preferences.html")
        self.assertEquals(identifier_store.discard_identifier.mock_calls, [
            call('joe', '=id'),
            ])

    def test_render_preference_panel_POST_delete_no_associations(self):
        req = self.make_request(authname='joe', method='POST',
                                args={'action': 'delete_associations'})
        self.assert_render_preference_panel_renders_panel(req)
        self.assertIn("No OpenIDs selected", req.chrome['warnings'][0])

    def test_match_request(self):
        prefs = self.get_component()
        req = self.make_request(path_info='/openid/associate')
        self.assertTrue(prefs.match_request(req))
        for path_info in '/', '/wiki', '/openid/logout':
            req = self.make_request(path_info=path_info)
            self.assertFalse(prefs.match_request(req))

    def test_process_request_not_logged_in(self):
        req = self.make_request(path_info='/openid/associate')
        prefs = self.get_component()
        with self.assertRaises(Redirected) as redirect:
            prefs.process_request(req)
        self.assertEquals(redirect.exception.url, req.href())

    def test_associate_response(self):
        req = self.make_request(authname='joe', path_info='/openid/associate')
        prefs = self.get_component()
        with patch.object(prefs.__class__, 'openid_consumer') \
                 as openid_consumer:
            with patch.object(prefs.__class__, 'identifier_store') \
                     as identifier_store:
                openid_consumer.complete.return_value = '=id'
                with self.assertRaises(Redirected) as redirect:
                    prefs.process_request(req)

        self.assertEquals(identifier_store.mock_calls, [
            call.add_identifier('joe', '=id'),
            ])
        self.assertEquals(redirect.exception.url, req.href.prefs('openid'))

    def test_associate_response_authn_fail(self):
        req = self.make_request(authname='joe', path_info='/openid/associate')
        prefs = self.get_component()
        with patch.object(prefs.__class__, 'openid_consumer') \
                 as openid_consumer:
            openid_consumer.complete.side_effect = AuthenticationFailed
            with self.assertRaises(Redirected) as redirect:
                prefs.process_request(req)
        self.assertIn("Authentication failed",
                      escape(req.chrome['warnings'][0]))

    def test_associate_response_identifier_in_use(self):
        req = self.make_request(authname='joe', path_info='/openid/associate')
        prefs = self.get_component()
        with patch.object(prefs.__class__, 'openid_consumer') \
                 as openid_consumer:
            with patch.object(prefs.__class__, 'identifier_store') \
                     as identifier_store:
                openid_consumer.complete.return_value = '=id'
                identifier_store.add_identifier.side_effect = (
                    OpenIDIdentifierInUse('joe', '=id'))
                with self.assertRaises(Redirected) as redirect:
                    prefs.process_request(req)
        self.assertIn("already associated", req.chrome['warnings'][0])

    def test_associate_response_no_such_user(self):
        req = self.make_request(authname='joe', path_info='/openid/associate')
        prefs = self.get_component()
        with patch.object(prefs.__class__, 'openid_consumer') \
                 as openid_consumer:
            with patch.object(prefs.__class__, 'identifier_store') \
                     as identifier_store:
                openid_consumer.complete.return_value = '=id'
                identifier_store.add_identifier.side_effect = (
                    UserNotFound("No such user"))
                with self.assertRaises(Redirected) as redirect:
                    prefs.process_request(req)
        self.assertIn("No such user", req.chrome['warnings'][0])


    def xtest_get_active_navigation_item(self):
        req = self.make_request()
        plugin = self.get_plugin()
        self.assertEquals(plugin.get_active_navigation_item(req),
                          "openid/login")

    def xtest_get_navigation_items(self):
        req = self.make_request(authname='anonymous')
        plugin = self.get_plugin()
        navitems = dict(
            ((cat, name), text)
            for cat, name, text in plugin.get_navigation_items(req))
        self.assertEquals(navitems.keys(), [('metanav', 'openid/login')])
        self.assertEquals(
            navitems['metanav', 'openid/login'].attrib.get('href'),
            req.href.openid('login', referer=req.href(req.path_info)))

    def xtest_get_navigation_items_when_logged_in(self):
        req = self.make_request(authname='not anonymous')
        plugin = self.get_plugin()
        navitems = list(plugin.get_navigation_items(req))
        self.assertEquals(len(navitems), 0)

    def xtest_get_htdocs_dirs(self):
        plugin = self.get_plugin()
        with patch('authopenid.authopenid.resource_filename') \
                 as resource_filename:
            self.assertEquals(plugin.get_htdocs_dirs(),
                              [('authopenid', resource_filename.return_value)])

    def xtest_get_templates_dirs(self):
        plugin = self.get_plugin()
        with patch('authopenid.authopenid.resource_filename') \
                 as resource_filename:
            self.assertEquals(plugin.get_templates_dirs(),
                              [resource_filename.return_value])

    def xtest_match_request(self):
        plugin = self.get_plugin()
        for path_info in '/openid/login', '/openid/response':
            req = self.make_request(path_info=path_info)
            self.assertTrue(plugin.match_request(req))
        for path_info in '/', '/wiki', '/openid/logout':
            req = self.make_request(path_info=path_info)
            self.assertFalse(plugin.match_request(req))

    def xtest_process_request_when_already_logged_in(self):
        req = self.make_request(path_info='/openid/login', method='POST',
                                args={'openid_identifier': '=id'},
                                authname="someuser")
        plugin = self.get_plugin()
        with self.assertRaises(Redirected) as caught:
            plugin.process_request(req)
        self.assertIn("Already logged in", req.chrome['warnings'])
        self.assertEquals(caught.exception.url, self.env.abs_href())

    def xtest_login_returns_form_for_GET(self):
        req = self.make_request(path_info='/openid/login')
        self.assert_process_request_shows_login_form(req)

    def xtest_login_sets_start_page_from_referer(self):
        req = self.make_request(path_info='/openid/login',
                                args={'referer': 'foo'})
        plugin = self.get_plugin()
        plugin.get_session(req)['key'] = 'value'
        plugin.process_request(req)
        self.assertEquals(plugin.get_session(req), {'start_page': 'foo'})

    def xtest_login_leaves_start_page_if_no_referer(self):
        req = self.make_request(path_info='/openid/login')
        plugin = self.get_plugin()
        plugin.get_session(req)['start_page'] = 'bar'
        plugin.process_request(req)
        self.assertEquals(plugin.get_session(req), {'start_page': 'bar'})

    def xtest_login_with_fancy_selector(self):
        req = self.make_request(path_info='/openid/login')
        plugin = self.get_plugin()
        with patch.object(plugin.__class__, 'fancy_selector') \
                 as fancy_selector:
            tmpl, data, ctype = plugin.process_request(req)
        self.assertIs(data['selector'],
                      fancy_selector.get_template_data.return_value)

    def xtest_login_POST(self):
        req = self.make_request(path_info='/openid/login', method='POST',
                                args={'openid_identifier': '=id'})
        plugin = self.get_plugin()
        with patch.object(plugin.__class__, 'openid_consumer') \
                 as openid_consumer:
            rv =plugin.process_request(req)
        self.assertIs(rv, openid_consumer.begin.return_value)
        self.assertEquals(openid_consumer.mock_calls, [
            call.begin(req, '=id', req.abs_href.openid('response'),
                       immediate=False),
            ])

    def xtest_login_GET_with_default_openid(self):
        default_openid = 'http://example.net/op'
        self.env.config.set('openid', 'default_openid', default_openid)
        req = self.make_request(path_info='/openid/login')
        plugin = self.get_plugin()
        with patch.object(plugin.__class__, 'openid_consumer') \
                 as openid_consumer:
            rv =plugin.process_request(req)
        self.assertIs(rv, openid_consumer.begin.return_value)
        self.assertEquals(openid_consumer.mock_calls, [
            call.begin(req, default_openid, req.abs_href.openid('response'),
                       immediate=False),
            ])

    def xtest_login_POST_with_no_identifier(self):
        req = self.make_request(path_info='/openid/login', method='POST')
        self.assert_process_request_shows_login_form(req)
        self.assertIn("Enter an OpenID identifier", req.chrome['warnings'])


    def xtest_login_POST_discovery_failure(self):
        req = self.make_request(path_info='/openid/login', method='POST',
                                args={'openid_identifier': '=id'})
        plugin = self.get_plugin()
        with patch.object(plugin.__class__, 'openid_consumer') \
                 as openid_consumer:
            openid_consumer.begin.side_effect = DiscoveryFailure("test", 404)
            self.assert_process_request_shows_login_form(req)
        self.assertIn("Discovery failure: test", req.chrome['warnings'])

    def xtest_response_logs_user_in(self):
        req = self.make_request(path_info='/openid/response')
        plugin = self.get_plugin()
        with patch.multiple(plugin.__class__,
                            openid_consumer=DEFAULT,
                            identifier_store=DEFAULT,
                            user_login=DEFAULT) as mocks:
            mocks['openid_consumer'].complete.return_value = '=id'
            mocks['identifier_store'].get_user.return_value = 'joe'
            plugin.process_request(req)

        self.assertEquals(mocks['user_login'].mock_calls, [
            call.login(req, 'joe', referer=ANY),
            ])

    def xtest_response_registers_user(self):
        req = self.make_request(path_info='/openid/response')
        plugin = self.get_plugin()
        with patch.multiple(plugin.__class__,
                            openid_consumer=DEFAULT,
                            identifier_store=DEFAULT,
                            registration_module=DEFAULT) as mocks:
            mocks['openid_consumer'].complete.return_value = '=id'
            mocks['identifier_store'].get_user.return_value = None
            rv = plugin.process_request(req)
        registration_module = mocks['registration_module']
        self.assertIs(rv, registration_module.register_user.return_value)
        self.assertEquals(registration_module.mock_calls, [
            call.register_user(req, '=id'),
            ])

    def xtest_response_redirects_to_login_page_on_failure(self):
        req = self.make_request(path_info='/openid/response')
        plugin = self.get_plugin()
        with patch.object(plugin.__class__, 'openid_consumer') \
                 as openid_consumer:
            openid_consumer.complete.side_effect = AuthenticationFailed
            with self.assertRaises(Redirected) as redirect:
                plugin.process_request(req)
        self.assertEquals(redirect.exception.url, req.href.openid('login'))
        self.assertIn("Authentication failed",
                      map(escape, req.chrome['warnings']))

    def xtest_get_session(self):
        req = self.make_request()
        plugin = self.get_plugin()
        plugin.get_session(req)['key'] = None
        self.assertIn(plugin.session_skey, req.session)
        plugin.get_session(req).clear()
        self.assertNotIn(plugin.session_skey, req.session)

    def xtest_get_start_page(self):
        req = self.make_request()
        plugin = self.get_plugin()
        plugin.get_session(req).update(start_page='/some/page')
        self.assertEquals(plugin.get_start_page(req),
                          'http://example.com/some/page')
        self.assertNotIn('start_page', plugin.get_session(req),
                         "'start_page' not popped from session")

    def xtest_get_start_page_default(self):
        req = self.make_request()
        plugin = self.get_plugin()
        self.assertEquals(plugin.get_start_page(req), self.env.abs_href())

    def xtest_get_start_page_does_not_redirect_to_self(self):
        req = self.make_request()
        plugin = self.get_plugin()
        plugin.get_session(req).update(start_page='/openid/subpage')
        self.assertEquals(plugin.get_start_page(req), self.env.abs_href())

    def xtest_get_start_page_clears_session(self):
        req = self.make_request()
        plugin = self.get_plugin()
        plugin.get_session(req).update(key='value')
        plugin.get_start_page(req)
        self.assertEquals(len(plugin.get_session(req)), 0)

    def xtest_get_start_page_preserves_session(self):
        req = self.make_request()
        plugin = self.get_plugin()
        plugin.get_session(req).update(key='value')
        plugin.get_start_page(req, clear_session=False)
        self.assertEquals(len(plugin.get_session(req)), 1)

class Redirected(Exception):
    @property
    def url(self):
        return self.args[0]

class MockSession(dict):
    def __init__(self, *args, **kwargs):
        dict.__init__(self, *args, **kwargs)
        self.get_session = Mock(name="get_session", spec=())

class MockRequest(Request):
    def __init__(self, base_url='http://example.com/',
                 path_info='', args={}, method='GET',
                 authname='anonymous'):
        environ = {
            'PATH_INFO': path_info,
            'trac.base_url': base_url,
            }
        if args and method != 'POST':
            environ['QUERY_STRING'] = urlencode(args)
        environ = webob.Request.blank(
            base_url, environ=environ,
            POST=args if method == 'POST' else None,
            ).environ
        start_response = Mock(name='start_response', spec=())
        Request.__init__(self, environ, start_response)
        self.session = MockSession()
        self.authname = authname
        self.locale = None

    def redirect(self, url, permanent=False):
        raise Redirected(url, permanent)
