from __future__ import absolute_import

import os

from unittest import defaultTestLoader
if not hasattr(defaultTestLoader, 'discover'): # pragma: no cover
    from unittest2 import defaultTestLoader

def suite():
    return defaultTestLoader.discover(os.path.dirname(__file__))
