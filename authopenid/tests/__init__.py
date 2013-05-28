from __future__ import absolute_import

from unittest import defaultTestLoader
if not hasattr(defaultTestLoader, 'discover'):
    from unittest2 import defaultTestLoader

def collector():
    return defaultTestLoader.discover('authopenid')
