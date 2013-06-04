from __future__ import absolute_import

import unittest
if not hasattr(unittest, 'skip'):
    import unittest2 as unittest

from genshi.builder import tag

class _TestBase(unittest.TestCase):
    def make_one(self, *args):
        import authopenid.api
        assert self.__class__.__name__.startswith('Test')
        class_name = self.__class__.__name__[4:]
        cls = getattr(authopenid.api, class_name)
        return cls(*args)

class TestOpenIDException(_TestBase):
    def test_default_message(self):
        exc = self.make_one()
        self.assertEquals(str(exc), exc.__class__.__name__)

    def test_html(self):
        exc = self.make_one('<foo>')
        self.assertEquals(unicode(exc.__html__()), u'&lt;foo&gt;')

    def test_unicode(self):
        exc = self.make_one('<foo>')
        self.assertEquals(unicode(exc), u'<foo>')

    def test_html_message(self):
        exc = self.make_one(tag.em('foo'))
        self.assertEquals(unicode(exc.__html__()), u'<em>foo</em>')
        self.assertEquals(str(exc), u'foo')

class TestSetupNeeded(_TestBase):
    def test_setup_url(self):
        setup_url = 'http://example.com/'
        exc = self.make_one(setup_url)
        self.assertEquals(exc.setup_url, setup_url)
        self.assertEquals(unicode(exc.__html__()),
                          u'<a href="%s">Setup needed</a>' % setup_url)

    def test_no_setup_url(self):
        exc = self.make_one()
        self.assertIs(exc.setup_url, None)
        self.assertEquals(unicode(exc.__html__()), u'Setup needed')

class TestAuthenticationFailed(_TestBase):
    def test_message(self):
        exc = self.make_one('reason', '=identity')
        self.assertEquals(exc.reason, 'reason')
        self.assertEquals(exc.identity_url, '=identity')
        self.assertEquals(
            unicode(exc.__html__()),
            u'Authentication failed for <code>=identity</code>: reason')

    def test_default_message(self):
        exc = self.make_one()
        self.assertEquals(exc.reason, None)
        self.assertEquals(exc.identity_url, None)
        self.assertEquals(unicode(exc.__html__()), u'Authentication failed')

class TestAuthenticationCancelled(_TestBase):
    def test_default_str(self):
        exc = self.make_one()
        self.assertRegexpMatches(str(exc), "Cancelled")

class TestOpenIDIdentifierInUse(_TestBase):
    def test_message(self):
        exc = self.make_one('user', '=identity')
        self.assertEquals(exc.username, 'user')
        self.assertEquals(exc.identifier, '=identity')
        self.assertEquals(unicode(exc.__html__()),
                          u'User <code>user</code> is already using'
                          u' identifier <code>=identity</code>')


class TestOpenIDIdentifier(_TestBase):
    def test_identifier(self):
        identifier = self.make_one('=ident')
        self.assertEquals(identifier, '=ident')
        self.assertEquals(identifier.identifier, '=ident')
