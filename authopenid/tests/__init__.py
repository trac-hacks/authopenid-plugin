from __future__ import absolute_import

from unittest import defaultTestLoader
if not hasattr(defaultTestLoader, 'discover'): # pragma: no cover
    from unittest2 import defaultTestLoader

def collector():                        # pragma: no cover
    return defaultTestLoader.discover('authopenid')
