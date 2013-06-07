from __future__ import absolute_import

from authopenid.authopenid import AuthOpenIdPlugin ; 'SIDE-EFFECTS'
# Make sure to import all modules which define trac components
from authopenid import (
    legacy,
    openid_consumer,
    openid_ext,
    identifier_store,
    register,
    preferences,
    openid_selector,
    userlogin,
    ) ; 'SIDE-EFFECTS'
