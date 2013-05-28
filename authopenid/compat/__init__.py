""" Helpers for running under older trac versions
"""
from __future__ import absolute_import

import trac

try:
    from trac.db.api import (
        TransactionContextManager,
        QueryContextManager,
        )
except ImportError:                     # pragma: no cover
    # trac < 1.0
    from authopenid.compat._dbapi import (
        TransactionContextManager,
        QueryContextManager,

        ModernizedComponent as Component,
        modernize_env,
        )
else:                                   # pragma: no cover
    from trac.core import Component

    def modernize_env(env):
        return env
