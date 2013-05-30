from __future__ import absolute_import

from unittest import defaultTestLoader
if not hasattr(defaultTestLoader, 'discover'): # pragma: no cover
    from unittest2 import defaultTestLoader

def suite():                            # pragma: no cover
    """ The complete suite of tests.

    This does not include meta-tests (tests for tests).
    """
    from authopenid.tests import functional
    suite = quick()
    suite.addTests(functional.suite())
    return suite

def quick():                            # pragma: no cover
    """ The non-slow tests

    Everything but the functional tests.
    """
    return defaultTestLoader.discover('authopenid')
