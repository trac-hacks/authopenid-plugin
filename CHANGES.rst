=======
Changes
=======

Next Release
============

Configuration Changes
---------------------

- **Security**: The default for ``[trac] check_auth_ip`` is now
  ``False``.  If you want authorization to be tied to the clients IP
  address *you must now explicitly set* this option to ``True``.

  Prior to this change, if ``check_auth_ip`` was not explicitly set, we
  ignored the global trac default (``False``) for the setting and behaved
  as if it were set to ``True``.

  This change is being made for the sake of backwards compatibility
  with trac 0.11 whose ``Configuration.has_option`` method does not
  support the optional ``defaults`` argument added in 0.12.  Without
  that there seems to be no clean way to determine whether a setting
  is explicitly set in the ``.ini`` file.


New Features
------------

- We will now use the json_ package if your python version includes it
  (python >= 2.6).   For older pythons, the simplejson_ package is now
  required.

.. _json: http://docs.python.org/library/json.html
.. _simplejson: https://github.com/simplejson/simplejson

Version 0.3.6 (2012-03-05)
==========================

New Maintainer
--------------

Jeff Dairiki has taken over maintenance of this plugin from
the original author, Dalius Dobravolskas (who no longer uses trac.)

The source repository for the plugin has moved to
https://github.com/dairiki/authopenid-plugin.

New Features
------------

- Respect the ``[trac] auth_cookie_lifetime`` config value when
  setting cookie expiration times.

Deprecations
------------

- Using the ``[trac] expires`` setting to specify the auth cookie lifetime
  is deprecated.  Use ``[trac] auth_cookie_lifetime`` instead.
  (The ``expires`` setting does not seem to exist in trac 0.12 or 0.11.)

Bug Fixes
---------

- Don't override the default value for the ``[trac] check_auth_ip``
  configuration setting.   Trac declares this to have a default value
  of *false*; we were overriding that default to *true*.

Version 0.3.5 (2011-10-04)
==========================


New Features
------------

- Now AX (as well as SREG) are attempted to get the user’s name.
  This is tested with Google (which does not support SREG).

- The new config setting ``[openid] lowercase_authname``
  specifies whether to force authnames to lowercase.
  For backwards compatibility, the default for this option is
  *true* (see below__).  In general, however, I think it makes
  more sense to set this option to *false*.

__ `authnames were being lower-cased`_


Bug Fixes
---------

- _`Authnames were being lower-cased` when recovering them from the cookie,
  but not when generating them initially.  This resulted — unless the
  user’s name was all lower case to start with — in two sessions being
  created upon initial login, one of which was ignored thereafter.

- Always uniquify authnames.  When they are lowercased, there’s always a
  chance of collision, even when they include the identity URL.
