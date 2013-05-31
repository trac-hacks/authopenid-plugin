from __future__ import absolute_import

import sys

if sys.version_info >= (2, 7):
    import unittest
else:
    import unittest2 as unittest

from trac.test import EnvironmentStub
from trac.web.api import RequestDone
from trac.web.href import Href

from openid import oidutil
from openid.consumer.consumer import SUCCESS, FAILURE, CANCEL, SETUP_NEEDED
from openid.consumer.discover import DiscoveryFailure

from mock import ANY, call, Mock, patch

from authopenid.api import (
    AuthenticationFailed,
    AuthenticationCancelled,
    SetupNeeded,
    )
from authopenid.compat import modernize_env

class Test_openid_logging_to(unittest.TestCase):
    def setUp(self):
        self.log = Mock(name='Logger')

    def capture_logging(self):
        from authopenid.openid_consumer import openid_logging_to
        return openid_logging_to(self.log)

    def test_capture(self):
        with self.capture_logging():
            oidutil.log("foo%s")
            oidutil.log("bar", 3)
        self.assertEqual(self.log.mock_calls, [
            call.warning("%s", "foo%s"),
            call.warning("%s", "bar"),
            ])

    def test_restore_original_logger(self):
        try:
            with self.capture_logging():
                raise DummyException()
        except DummyException:
            pass
        self.assertEqual(oidutil.log.__module__, 'openid.oidutil')

    def test_openid_switched_to_stock_logging(self):
        # XXX: The current git version of python-openid has switched
        # to using the stock logging module.  When that happens, our
        # capture_openid_logging context manager is going to have to
        # be reworked.
        self.assertFalse(
            hasattr(oidutil, 'logging'),
            msg="python-openid appears to have switch to using stock logging")


class OIDConsumerTestMixin(object):
    BASE_URL = 'http://example.net/trac'

    def get_consumer(self):
        from authopenid.openid_consumer import OpenIDConsumer
        return OpenIDConsumer(self.env)

    def get_request(self):
        req = Mock(name='Request')
        req.session = dict()
        req.authname = 'anonymous'
        req.abs_href = Href(self.BASE_URL)
        def redirect(url, permanent=False):
            raise Redirected(url, permanent)
        req.redirect.side_effect = redirect
        return req

    def consumer_begin(self,
                       identifier='http://example.net/',
                       return_to='http://example.com/'):
        consumer = self.get_consumer()
        req = self.get_request()
        return consumer.begin(req, identifier, return_to)

class TestOpenIDConsumer(unittest.TestCase, OIDConsumerTestMixin):

    def setUp(self):
        from authopenid.openid_consumer import OpenIDConsumer

        self.extension_providers = []
        patcher = patch.object(OpenIDConsumer, 'openid_extension_providers',
                               self.extension_providers)
        self.addCleanup(patcher.stop)
        consumer_class = patcher.start()

        patcher = patch.object(OpenIDConsumer, 'consumer_class')
        self.addCleanup(patcher.stop)
        consumer_class = patcher.start()


        self.oid_consumer = consumer_class.return_value

        self.auth_request = self.oid_consumer.begin.return_value
        self.auth_request.shouldSendRedirect.return_value = False

        self.response = self.oid_consumer.complete.return_value
        self.response.status = SUCCESS
        self.response.endpoint.canonicalID = None
        self.response.identity_url = 'IDENTITY'

        self.env = EnvironmentStub()


    def consumer_complete(self):
        consumer = self.get_consumer()
        req = self.get_request()
        return consumer.complete(req)

    def test_begin_discovery_failure(self):
        self.oid_consumer.begin.side_effect = DiscoveryFailure('msg', 'status')

        with self.assertRaises(DiscoveryFailure):
            self.consumer_begin()

    def test_begin_redirect(self):
        self.auth_request.shouldSendRedirect.return_value = True

        with self.assertRaises(Redirected):
            self.consumer_begin()

    def test_begin_autosubmit(self):
        auth_request = self.auth_request
        auth_request.shouldSendRedirect.return_value = False

        consumer = self.get_consumer()
        req = self.get_request()
        with self.assertRaises(RequestDone):
            consumer.begin(req, 'http://example.net', 'http://example.com/')

        form_html = auth_request.htmlMarkup.return_value
        self.assertIn(call.send(form_html, "text/html"), req.mock_calls)


    def test_begin_with_extension_providers(self):
        provider = Mock(name='provider')
        self.extension_providers.append(provider)

        with self.assertRaises(RequestDone):
            self.consumer_begin()
        self.assertEqual(provider.mock_calls, [
            call.add_to_auth_request(ANY, self.auth_request)])

    def test_complete(self):
        identifier = self.consumer_complete()
        self.assertEqual(str(identifier), self.response.identity_url)

    def test_complete_iname(self):
        self.response.endpoint.canonicalID = 'INAME'
        identifier = self.consumer_complete()
        self.assertEqual(str(identifier), 'INAME')

    def test_complete_with_extension_providers(self):
        provider = Mock(name='provider')
        data = (('a', 'b'), ('c', 'd'))
        def parse_response(response, identifier):
            for k, v in data:
                identifier.signed_data.add(k, v)
        provider.parse_response = parse_response
        self.extension_providers.append(provider)

        identifier = self.consumer_complete()
        self.assertEqual(set(identifier.signed_data.items()), set(data))

    def test_complete_failure(self):
        self.response.status = FAILURE
        with self.assertRaises(AuthenticationFailed):
            self.consumer_complete()

    def test_complete_cancelled(self):
        self.response.status = CANCEL
        with self.assertRaises(AuthenticationCancelled):
            self.consumer_complete()

    def test_complete_setup_needed(self):
        self.response.status = SETUP_NEEDED
        with self.assertRaises(SetupNeeded):
            self.consumer_complete()

    def assert_trust_root_equals(self, trust_root):
        consumer = self.get_consumer()
        req = self.get_request()
        self.assertEquals(consumer._get_trust_root(req), trust_root)

    def test_get_trust_root(self):
        self.assert_trust_root_equals('http://example.net/')

    def test_get_trust_root_project(self):
        self.env.config.set('openid', 'absolute_trust_root', False)
        self.assert_trust_root_equals('http://example.net/trac/')



class TestOpenIDConsumerIntegration(unittest.TestCase, OIDConsumerTestMixin):
    """ Currently this tests that the IEnvironmentSetupParticipant methods
    work with sqlite.

    XXX: should be fixed to work with other db schemes.
    """

    def setUp(self):
        self.env = EnvironmentStub()
        #assert self.env.dburi == 'sqlite::memory:'

    def tearDown(self):
        #self.env.global_databasemanager.shutdown()
        self.env.destroy_db()

    def test_begin_with_no_identifier_fails(self):
        with self.assertRaises(Exception):
            self.consumer_begin(identifier=None)

    def test_begin_with_crap_identifier_fails(self):
        with self.assertRaises(DiscoveryFailure):
            self.consumer_begin(identifier='foo')

    def list_tables(self):
        from authopenid.util import list_tables
        return set(list_tables(self.env))

    def assertOIDTablesExist(self):
        tables = self.list_tables()
        for table in 'oid_associations', 'oid_nonces':
            self.assertIn(table, tables)

    def assertOIDTablesMissing(self):
        tables = self.list_tables()
        for table in 'oid_associations', 'oid_nonces':
            self.assertNotIn(table, tables)

    def assert_schema_version_is(self, expected_version):
        env = modernize_env(self.env)
        consumer = self.get_consumer()
        system = dict(env.db_query("SELECT name, value FROM system"))
        version = system.get(consumer.schema_version_key)
        version = int(version) if version is not None else None
        self.assertEquals(version, expected_version,
                          "Expected schema version %r, got %r"
                          % (expected_version, version))

    def test_environment_created(self):
        consumer = self.get_consumer()
        consumer.environment_created()
        self.assertOIDTablesExist()
        self.assert_schema_version_is(1)

    def test_environment_upgrade_from_scratch(self):
        env = modernize_env(self.env)
        consumer = self.get_consumer()
        with env.db_query as db:
            self.assertTrue(consumer.environment_needs_upgrade(db))
        with env.db_transaction as db:
            consumer.upgrade_environment(db)
        with env.db_query as db:
            self.assertFalse(consumer.environment_needs_upgrade(db))
        self.assertOIDTablesExist()
        self.assert_schema_version_is(1)

    def test_environment_upgrade_from_legacy(self):
        # Fake legacy install: have tables, but no entry in system table
        env = modernize_env(self.env)
        consumer = self.get_consumer()
        with env.db_transaction as db:
            consumer.upgrade_environment(db)
            db("DELETE FROM system WHERE name=%s",
               (consumer.schema_version_key,))

        self.test_environment_upgrade_from_scratch()


class DummyException(Exception):
    pass

class Redirected(Exception):
    @property
    def url(self):
        return self.args[0]
