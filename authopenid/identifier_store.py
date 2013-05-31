''' Manage the association of OpenID identifiers with trac users
'''
from __future__ import absolute_import

from trac.core import implements
from trac.web.session import DetachedSession

from authopenid.api import (
    IOpenIDIdentifierStore,
    UserNotFound,
    OpenIDIdentifierInUse,
    )
from authopenid.compat import Component

class OpenIDIdentifierStore(Component):
    """ Helper for managing trac 'user accounts'

    """
    implements(IOpenIDIdentifierStore)

    # FIXME: support multiple identifiers per user. (requires our own
    # db table to record the associations, I think)
    # (This would be good as the new table would be indexed by identifier
    # as well.)
    #
    # FIXME: should store email with identifier so that something better
    # than
    #  https://www.google.com/accounts/o8/id?id=AItOawlE_gp4kdNs7K0Lh0HAc__hJgi2eZnajM4
    # can be shown to the user on the "here are the openid identifiers
    # associated with your account" panel.

    # FIXME: handle username case

    identifier_skey = 'openid_session_identity_url_data'

    def get_user(self, openid_identifier):
        """ Look up username by OpenID identifier

        In the case that multiple users match, the one who has most
        recently logged in will be returned.

        :returns: username or ``None``.
        """
        with self.env.db_query as db:
            rows = db("SELECT session.sid"
                      " FROM session"
                      "  LEFT OUTER JOIN session_attribute AS attr"
                      "                  USING(sid, authenticated)"
                      " WHERE session.authenticated=%s"
                      "       AND attr.name=%s AND attr.value=%s"
                      " ORDER BY session.last_visit DESC",
                      (1, self.identifier_skey, openid_identifier))
        if len(rows) == 0:
            return None
        elif len(rows) > 1:
            # Multiple users matched.  (We will return the one who most
            # recently logged in.)

            # FIXME: Probably should provide a config option which
            # controls whether this is a error or not.
            self.log.warning(
                "Mutiple users share the same openid identifier: %s",
                ', '.join(repr(user) for (user,) in rows))
        return rows[0][0]

    def get_identifiers(self, username):
        """ Return an iterable of OpenID identifiers associated with user

        :rtype: sequence
        :raises: :exc:`UserNotFound` if no user is found for ``username``
        """
        user = self._get_detached_session(username) # raises UserNotFound
        if self.identifier_skey in user:
            return set(user[self.identifier_skey])
        else:
            return set()

    def add_identifier(self, username, openid_identifier):
        """ Add an OpenID identifier for the user

        .. FIXME:: current this replaces any exisitng identifier associated
            with the user (since we do not currently support multiple
            identifiers per user.)

        :raises: :exc:`UserNotFound` if no user is found for ``username``
        :raises: :exc:`OpenIDIdentifierInUse` if another user is already
            associated with the ``openid_identifier``
        """
        user = self._get_detached_session(username) # raises UserNotFound
        if self.get_user(openid_identifier) not in (None, user.sid):
            raise OpenIDIdentifierInUse(username, openid_identifier)

        existing = user.get(self.identifier_skey)
        if existing and existing != openid_identifier:
            self.log.warning(
                "Replacing existing openid identifier %r for user %r",
                existing, username)

        user[self.identifier_skey] = openid_identifier
        user.save()

    def discard_identifier(self, username, openid_identifier):
        """ Remove an OpenID identifier for the user

        :raises: :exc:`UserNotFound` if no user is found for ``username``
        """
        user = self._get_detached_session(username) # raises UserNotFound
        try:
            if user[self.identifier_skey] == openid_identifier:
                del user[self.identifier_skey]
        except KeyError:
            pass
        else:
            user.save()

    def _get_detached_session(self, username):
        username = self._maybe_lowercase_username(username)
        ds = DetachedSession(self.env, username)
        # XXX: DetachedSession._new is not public api, but seems to be
        # the cleanest way to detect non-existing sessions.  An
        # alternative would be to check for ``ds.last_visit == 0 and
        # len(ds) == 0``.
        if ds._new:
            raise UserNotFound("No such user: %r", username)
        return ds

    # FIXME: unify with the same method in OpenIDLegacyRegistrationModule
    def _maybe_lowercase_username(self, username):
        if self.config.getbool('trac', 'ignore_auth_case'):
            return username.lower()
        return username
