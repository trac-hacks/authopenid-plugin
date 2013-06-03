from __future__ import absolute_import

from authopenid.authopenid import AuthOpenIdPlugin ; 'SIDE-EFFECTS'
# Make sure to import all modules which define trac components
from authopenid import (
    openid_consumer,
    openid_ext,
    identifier_store,
    authorization,
    register,
    preferences,
    openid_selector,
    userlogin,
    ) ; 'SIDE-EFFECTS'
