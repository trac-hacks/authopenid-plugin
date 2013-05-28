""" Helpers for running under older trac versions
"""
from __future__ import absolute_import

try:
    from trac.db.api import (
        TransactionContextManager,
        QueryContextManager,
        )                               ; 'SIDE-EFFECTS'
except ImportError:                     # pragma: no cover
    # trac < 1.0
    from authopenid.compat._dbapi import (
        TransactionContextManager,
        QueryContextManager,

        ModernizedComponent as Component,
        modernize_env,
        )                               ; 'SIDE-EFFECTS'
else:                                   # pragma: no cover
    from trac.core import Component     ; 'SIDE-EFFECTS'

    def modernize_env(env):
        return env
