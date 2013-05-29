from __future__ import absolute_import

from unittest import defaultTestLoader
if not hasattr(defaultTestLoader, 'discover'): # pragma: no cover
    from unittest2 import defaultTestLoader

def suite():                            # pragma: no cover
    suite = unit_tests()
    suite.addTests(functional_tests())
    return suite

def unit_tests():                       # pragma: no cover
    return defaultTestLoader.discover('authopenid.tests')

def functional_tests():                 # pragma: no cover
    return defaultTestLoader.discover('authopenid.tests', 'functional.py')

def compat_tests():                     # pragma: no cover
    return defaultTestLoader.discover('authopenid.tests.compat')
