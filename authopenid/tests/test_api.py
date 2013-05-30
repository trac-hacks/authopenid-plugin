from __future__ import absolute_import

import unittest
if not hasattr(unittest, 'skip'):
    import unittest2 as unittest

class TextAuthenticationCancelled(unittest.TestCase):
    def make_one(self, *args):
        from authopenid.api import AuthenticationCancelled
        return AuthenticationCancelled(*args)

    def test_default_str(self):
        exc = self.make_one()
        self.assertRegexpMatches(str(exc), "Cancelled")
