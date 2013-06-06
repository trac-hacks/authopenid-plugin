# -*- coding: utf-8 -*-
from __future__ import absolute_import

from itertools import islice
import unittest
if not hasattr(unittest, 'skipIf'):
    import unittest2 as unittest

from mock import Mock, patch, call, ANY
import webob

from trac.perm import PermissionSystem
from trac.test import EnvironmentStub
from trac.web.api import Request
from trac.web.chrome import Chrome
from trac.web.session import DetachedSession

from authopenid.api import NotAuthorized, OpenIDIdentifier

class _TestBase(unittest.TestCase):
    def setUp(self):
        # make sure the identifier, and UserLogin are available
        from authopenid import identifier_store, userlogin ; 'SIDE-EFFECTS'

        self.env = EnvironmentStub(enable=[
            'trac.*',
            'authopenid.identifier_store.*',
            'authopenid.userlogin.*',
            'authopenid.register.*',
            ])
        #assert self.env.dburi == 'sqlite::memory:'

        self.req = MockRequest()
        Chrome(self.env).prepare_request(self.req)

    def tearDown(self):
        self.env.destroy_db()

    def create_user(self, username, identifier=None):
        from authopenid.identifier_store import OpenIDIdentifierStore
        ds = DetachedSession(self.env, username)
        ds['name'] = username
        if identifier:
            ds[OpenIDIdentifierStore.identifier_skey] = ident(identifier)
        ds.save()

class TestOpenIDInteractiveRegistrationModule(_TestBase):
    def get_registration_module(self):
        from authopenid.register import OpenIDInteractiveRegistrationModule
        return OpenIDInteractiveRegistrationModule(self.env)

    def test_register_user(self):
        from authopenid.authopenid import AuthOpenIdPlugin
        identifier = ident('=id')
        reg = self.get_registration_module()
        with patch('authopenid.register.RegistrationHelper') as helper:
            tmpl, data, ctype = reg.register_user(self.req, identifier)
        self.assertEquals(tmpl, 'openid_register.html')
        self.assertEquals(data['register_url'], '/openid/register')
        self.assertEquals(data['username'], '')
        oid_session = AuthOpenIdPlugin(self.env).get_session(self.req)
        self.assertEquals(oid_session['register.identifier'], '=id')

    def test_register_user_not_authorized(self):
        identifier = ident('=id')
        reg = self.get_registration_module()
        with patch('authopenid.register.RegistrationHelper') as helper:
            helper().check_authorization.side_effect=NotAuthorized
            with self.assertRaises(Redirected):
                reg.register_user(self.req, identifier)

    def test_register_user_checks_suggested_usernames(self):
        identifier = ident('=id')
        reg = self.get_registration_module()
        with patch('authopenid.register.RegistrationHelper') as helper:
            helper().suggested_usernames.return_value=['A', 'B']
            helper().maybe_lowercase_username = lambda name: name.lower()
            helper().is_valid_username = lambda name: name == 'b'
            tmpl, data, ctype = reg.register_user(self.req, identifier)
        self.assertEquals(data['username'], 'b')

    def test_get_htdocs_dirs(self):
        reg = self.get_registration_module()
        with patch('authopenid.register.resource_filename') \
                 as resource_filename:
            self.assertEquals(reg.get_htdocs_dirs(), [
                ('authopenid', resource_filename.return_value),
                ])

    def test_get_templates_dirs(self):
        reg = self.get_registration_module()
        with patch('authopenid.register.resource_filename') \
                 as resource_filename:
            self.assertEquals(reg.get_templates_dirs(), [
                resource_filename.return_value,
                ])

    def test_match_request(self):
        reg = self.get_registration_module()
        self.assertFalse(reg.match_request(self.req))

        self.req.environ['PATH_INFO'] = '/openid/register'
        self.assertTrue(reg.match_request(self.req))

    def test_process_request(self):
        from authopenid.authopenid import AuthOpenIdPlugin
        oid_session = AuthOpenIdPlugin(self.env).get_session(self.req)
        oid_session['register.identifier'] = '=id'

        self.req.environ['QUERY_STRING'] = 'username=joe'

        reg = self.get_registration_module()
        with patch('authopenid.register.RegistrationHelper') as helper:
            with self.assertRaises(Redirected):
                helper().maybe_lowercase_username = lambda name: name
                reg.process_request(self.req)

        self.assertEquals(helper().create_user.mock_calls, [
            call('joe', '=id', ANY),
            ])

        oid_session = AuthOpenIdPlugin(self.env).get_session(self.req)
        self.assertNotIn('register.identifier', oid_session)

    def test_process_request_invalid_username(self):
        # FIXME: move InvalidUsername to api.py?
        from authopenid.register import InvalidUsername
        from authopenid.authopenid import AuthOpenIdPlugin
        oid_session = AuthOpenIdPlugin(self.env).get_session(self.req)
        oid_session['register.identifier'] = '=id'

        reg = self.get_registration_module()
        with patch('authopenid.register.RegistrationHelper') as helper:
            error = InvalidUsername('joe')
            helper().create_user.side_effect = error
            with patch('authopenid.register.chrome') as chrome:
                tmpl, data, ctype = reg.process_request(self.req)
        self.assertEquals(tmpl, 'openid_register.html')
        self.assertEquals(chrome.add_warning.mock_calls, [
            call(self.req, error)
            ])

    def test_process_request_no_identifier(self):
        reg = self.get_registration_module()
        with self.assertRaises(Redirected) as caught:
            reg.process_request(self.req)
        self.assertEquals(caught.exception.url, '/')

    def test_process_request_when_already_logged_in(self):
        self.req.authname = 'joe'
        reg = self.get_registration_module()
        with patch('authopenid.register.chrome') as chrome:
            with self.assertRaises(Redirected):
                reg.process_request(self.req)
        self.assertEquals(chrome.add_warning.mock_calls, [
            call(self.req, "Already logged in!")
            ])

class TestOpenIDLegacyRegistrationModule(_TestBase):
    #FIXME: needs cleanup

    def get_registration_module(self):
        from authopenid.register import OpenIDLegacyRegistrationModule
        return OpenIDLegacyRegistrationModule(self.env)

    def test_register_user(self):
        reg = self.get_registration_module()
        with patch('authopenid.register.RegistrationHelper') as helper:
            helper().suggested_usernames.return_value = ['joe']
            helper().maybe_lowercase_username = lambda name: name
            with self.assertRaises(Redirected):
                reg.register_user(self.req, ident('=id'))

        self.assertEquals(helper().create_user.mock_calls, [
            call('joe', '=id', ANY),
            ])

    def test_register_user_not_authorized(self):
        reg = self.get_registration_module()
        with patch('authopenid.register.RegistrationHelper') as helper:
            helper().check_authorization.side_effect = NotAuthorized
            with self.assertRaises(Redirected):
                reg.register_user(self.req, ident('=id'))

    def test_register_user_with_existing_users(self):
        # FIXME: move InvalidUsername, UserExists to api.py?
        from authopenid.register import InvalidUsername, UserExists
        def create_user(username, oid_identifier, user_attr):
            if username == 'INVALID':
                raise InvalidUsername(username)
            elif not username.endswith('(3)'):
                raise UserExists(username)

        reg = self.get_registration_module()
        with patch('authopenid.register.RegistrationHelper') as helper:
            helper().suggested_usernames.return_value = ['INVALID', 'joe']
            helper().maybe_lowercase_username = lambda name: name
            helper().create_user = Mock(wraps=create_user)
            with self.assertRaises(Redirected):
                reg.register_user(self.req, ident('=id'))

        self.assertEquals(helper().create_user.mock_calls, [
            call('INVALID', '=id', ANY),
            call('joe', '=id', ANY),
            call('joe (2)', '=id', ANY),
            call('joe (3)', '=id', ANY),
            ])

    def test_register_user_no_suggested_usernames(self):
        reg = self.get_registration_module()
        with patch('authopenid.register.RegistrationHelper') as helper:
            helper().suggested_usernames.return_value = []
            helper().maybe_lowercase_username = lambda name: name
            with self.assertRaises(Redirected) as caught:
                reg.register_user(self.req, ident('=id'))

        self.assertEquals(helper().create_user.mock_calls, [])
        self.assertEquals(caught.exception.url, '/openid/login')


    def test_uniquify_usernames(self):
        reg = self.get_registration_module()
        candidates = ['a', 'b']
        self.assertEquals(list(islice(reg._uniquify_usernames(candidates),
                                      0, 4)),
                          ['a (2)', 'b (2)', 'a (3)', 'b (3)'])

    def test_uniquify_usernames_with_no_candidates(self):
        reg = self.get_registration_module()
        self.assertEquals(list(reg._uniquify_usernames([])), [])


class TestRegistrationHelper(_TestBase):
    def get_helper(self):
        from authopenid.register import RegistrationHelper
        return RegistrationHelper(self.env)

    def assert_username_for_identifier_is(self, identifier, username):
        from authopenid.identifier_store import OpenIDIdentifierStore
        store = OpenIDIdentifierStore(self.env)
        self.assertEquals(store.get_user(identifier), username,
                          "username mismatch for identifier %r" % identifier)

    def test_maybe_lowercase_username(self):
        helper = self.get_helper()
        self.assertEquals(helper.maybe_lowercase_username('Foo'), 'Foo')
        self.env.config.set('trac', 'ignore_auth_case', True)
        self.assertEquals(helper.maybe_lowercase_username('Foo'), 'foo')

    def test_create_user(self):
        helper = self.get_helper()
        helper.create_user('joe', '=id', {'name': 'Joseph'})
        ds = DetachedSession(self.env, 'joe')
        self.assertEqual(ds['name'], 'Joseph')
        self.assert_username_for_identifier_is('=id', 'joe')

    def test_create_user_with_no_attributes(self):
        helper = self.get_helper()
        helper.create_user('joe')
        ds = DetachedSession(self.env, 'joe')
        self.assertFalse(ds._new)
        self.assertEquals(len(ds), 0)

    def test_create_user_fails_if_user_exists(self):
        # FIXME: move UserExists to api.py?
        from authopenid.register import UserExists
        self.create_user('joe', '=not*joe')
        helper = self.get_helper()
        with self.assertRaises(UserExists):
            helper.create_user('joe', '=id', {'name': 'Joseph'})

    def test_create_user_fails_if_username_improperly_cased(self):
        self.env.config.set('trac', 'ignore_auth_case', True)
        helper = self.get_helper()
        with self.assertRaises(ValueError):
            helper.create_user('Joe')

    def test_create_user_calls_check_username(self):
        helper = self.get_helper()
        with patch.object(helper, 'check_username') as check_username:
            helper.create_user('Joe')
        self.assertEqual(check_username.mock_calls, [call('Joe')])

    def test_check_username_raises_invalid_username(self):
        # FIXME: move InvalidUsername to api.py?
        from authopenid.register import InvalidUsername
        helper = self.get_helper()
        for username in ('', ' foo', 'bar ', 'ALL_CAPS', 'Anonymous',
                         'authenticated', 'bad[chars]'):
            with self.assertRaises(InvalidUsername):
                helper.check_username(username)

    def test_check_username_fails_if_permissions_exists(self):
        # FIXME: move UserExists to api.py?
        from authopenid.register import UserExists
        ps = PermissionSystem(self.env)
        some_action = ps.get_actions()[0]
        ps.grant_permission('some_group', some_action)

        helper = self.get_helper()
        with self.assertRaises(UserExists):
                helper.check_username('some_group')

    def test_is_valid_username(self):
        helper = self.get_helper()
        self.assertTrue(helper.is_valid_username('user'))
        self.assertFalse(helper.is_valid_username('ALLCAPS'))

    def assert_suggested_usernames_are(self, suggestions):
        helper = self.get_helper()
        usernames = helper.suggested_usernames(self.req, ident('=id'))
        self.assertEquals(list(usernames), suggestions)

    def test_suggested_usernames_no_fallback(self):
        helper = self.get_helper()
        with patch.object(helper.__class__, 'registration_participants', []):
            self.assert_suggested_usernames_are([])

    def test_suggested_usernames_with_fallback(self):
        helper = self.get_helper()
        with patch.object(helper.__class__, 'registration_participants', []):
            self.assertEquals(
                list(helper.suggested_usernames(self.req, ident('=id'),
                                                fallback_to_identifier=True)),
                ['=id'])

    def test_suggested_usernames_handles_string_suggestion(self):
        helper = self.get_helper()
        participant = Mock(name="RegistrationParticipant")
        participant.suggest_username.return_value = 'Suggestion'
        with patch.object(helper.__class__, 'registration_participants',
                          [participant]):
            self.assert_suggested_usernames_are(['Suggestion'])

    def test_suggested_usernames_handles_iterable_suggestion(self):
        helper = self.get_helper()
        participant = Mock(name="RegistrationParticipant")
        participant.suggest_username.return_value=['Foo', 'Bar']
        with patch.object(helper.__class__, 'registration_participants',
                          [participant]):
            self.assert_suggested_usernames_are(['Foo', 'Bar'])

    def test_suggested_usernames_handles_no_suggestion(self):
        helper = self.get_helper()
        participant = Mock(name="RegistrationParticipant")
        participant.suggest_username.return_value = None
        with patch.object(helper.__class__, 'registration_participants',
                          [participant]):
            self.assert_suggested_usernames_are([])

    def test_suggested_usernames_case_insensitive(self):
        self.env.config.set('trac', 'ignore_auth_case', True)
        helper = self.get_helper()
        participant = Mock(name="RegistrationParticipant")
        participant.suggest_username.return_value = ['Foo', 'foo']
        with patch.object(helper.__class__, 'registration_participants',
                          [participant]):
            self.assert_suggested_usernames_are(['Foo'])

    def test_user_attributes(self):
        self.env.config.set('trac', 'ignore_auth_case', True)
        helper = self.get_helper()
        participant1 = Mock(name="RegistrationParticipant1")
        participant2 = Mock(name="RegistrationParticipant1")
        participant1.get_user_data.return_value = {'name': 'Name'}
        participant2.get_user_data.return_value = {'name': 'Other',
                                                   'email': 'address'}
        with patch.object(helper.__class__, 'registration_participants',
                          [participant1, participant2]):
            self.assertEquals(helper.user_attributes(self.req, ident('=id')),
                              {'name': 'Name', 'email': 'address'})

    def test_user_attributes_handles_no_attributes(self):
        self.env.config.set('trac', 'ignore_auth_case', True)
        helper = self.get_helper()
        participant = Mock(name="RegistrationParticipant1")
        participant.get_user_data.return_value = None
        with patch.object(helper.__class__, 'registration_participants',
                          [participant]):
            self.assertEquals(helper.user_attributes(self.req, ident('=id')),
                              {})



def ident(s, *args, **kwargs):
    identifier = OpenIDIdentifier(s)
    identifier.signed_data.update(*args, **kwargs)
    return identifier

class Redirected(Exception):
    @property
    def url(self):
        return self.args[0]

class MockRequest(Request):
    def __init__(self, base_url='http://example.net/', authname='anonymous'):
        environ = webob.Request.blank(base_url).environ
        start_response = Mock(name='start_response', spec=())
        Request.__init__(self, environ, start_response)
        self.authname = authname
        self.locale = None
        self.session = dict()

    def redirect(self, url, permanent=False):
        raise Redirected(url, permanent)

    @property
    def start_response(self):
        return self._start_response
