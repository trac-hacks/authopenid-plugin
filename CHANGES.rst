=======
Changes
=======

Big Rewrite In Progress
=======================

Non Backward-Compatible Configuration Changes
---------------------------------------------

- The ``[openid] timeout`` configuration variable is no longer
  supported.  (It was only of marginal use, in any case.)

We now use the stock ``trac.web.auth.LoginModule`` to handle the auth
cookie manipulations.  (We were already using its ``auth_cookie``
table.)  Because of this:

- The ``[openid] lowercase_authname`` configuration variable is no
  longer supported.  You should now use ``[trac] ignore_auth_case``,
  which does the same thing, instead.  Note, however, that the default
  for ``lowercase_authname`` was ``True``, while the default for
  ``ignore_auth_case`` is ``False``.  The latter generally makes more
  sense, however changing this is *backwards-incompatible* if you
  already have user sessions which you would like to preserve. (So, if
  you had ``lowercase_authname=false``, just delete it — you're all
  good.  Otherwise you should set ``ignore_auth_case=true`` in your
  ``[trac]`` section.)

- The ``[trac] check_auth_ip_mask`` configuration variable is no longer
  supported.

- The default value for ``[trac] auth_cookie_lifetime`` has changed.
  We used to use a default of 24 hours, however the stock ``LoginModule``
  has always used a default of 0 (cookie expires at the end of the browser
  session).  We now use that default as well.


Next Version
============

Bug Fixes
---------

- Previously, if no email address was returned via AX or SREG, the
  ``email_white_list`` config option was being ignored.  Now if
  ``email_white_list`` is set and no email address can be determined,
  authorization will be denied.

Documentation
-------------

- Updated the example config in the README__ so that it more closely
  matches current reality.  (Baby steps...)

__ https://github.com/dairiki/authopenid-plugin#options

Version 0.4.3 (2013-05-22)
==========================

Bug Fixes
---------

- Fix so that ``check_list_username`` actually works.  Now one can
  actually use the ``check_list`` web API to implement custom identity
  to username mapping.

- Fall back to using the identifier URL as the authname (rather than
  throwing an exception) if the OpenID provider did not return a full
  name (or nickname).

Packaging
---------

- README.rst: Patrick Uiterwijk has packaged this plugin for Fedora


Version 0.4.2 (2013-03-24)
==========================

New Features
------------

These features were contributed by Patrick Uiterwijk.

- New config option ``use_nickname_as_authname``.  If set, the OpenID
  nickname will be used for the authname (or trac username).

- New config option ``trust_authname``.  If set, trust the
  OpenID-derived authname to be unique.  **Security warning**: do not
  set this unless you know what you are doing.


Version 0.4.1 (2012-06-25)
==========================

This is a brown bag release.  Release 0.4 was unusable.

Bug Fixes
---------

- Packaging: A number of crucial files were omitted from the manifest.

Version 0.4 (2012-06-25)
========================

Configuration Changes
---------------------

- The default for ``[trac] check_auth_ip`` is now ``False``.  **This
  has security implications**.  If you want authorization to be tied
  to the clients IP address *you must now explicitly set* this option
  to ``True``.

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


- A minor hack has been made which allows at least basic functionality
  under the development branch, trac-1.0 (formerly know as trac-0.13).
  Note that only very basic tests under trac-1.0 have not been
  performed.  (The code in this plugin still does not adhere to
  the modern `trac db API`_ usage recommendations.)

.. _json: http://docs.python.org/library/json.html
.. _simplejson: https://github.com/simplejson/simplejson
.. _trac db API: http://trac.edgewall.org/wiki/TracDev/DatabaseApi

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
