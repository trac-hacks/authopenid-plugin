import sys

if sys.version_info >= (2, 7):
    import unittest
else:
    import unittest2 as unittest

BASE_URL = 'http://example.com/trac/'

class Test_sanitize_referer(unittest.TestCase):
    def sanitize(self, referer, base_url=BASE_URL):
        from authopenid.util import sanitize_referer
        return sanitize_referer(referer, base_url)

    def test_base(self):
        self.assertEqual(self.sanitize(BASE_URL), BASE_URL)

    def test_none(self):
        self.assertIs(self.sanitize(None), None)

    def test_relative(self):
        self.assertEqual(self.sanitize('page'), BASE_URL + 'page')

    def test_absolute(self):
        self.assertEqual(self.sanitize(BASE_URL + 'page'), BASE_URL + 'page')

    def test_trailing_slash(self):
        self.assertEqual(self.sanitize(BASE_URL + 'page/'), BASE_URL + 'page/')

    def test_unsafe(self):
        self.assertIs(self.sanitize(BASE_URL + '../page'), None)

    def test_different_scheme(self):
        self.assertIs(self.sanitize(BASE_URL.replace('http:', 'https:')), None)

    def test_different_host(self):
        self.assertIs(self.sanitize(BASE_URL.replace('.com/', '.net/')), None)

class Test_split_path_info(unittest.TestCase):
    def test(self):
        from authopenid.util import split_path_info

        for path, expect in [
            ('/a', '/a'),
            ('/a/', '/a'),
            ('/a/./b', '/a/b'),
            ('/a/../b', '/b'),
            ('/a/../../b', '/b'),
            ]:
            self.assertEqual(split_path_info(path), expect.split('/'))
