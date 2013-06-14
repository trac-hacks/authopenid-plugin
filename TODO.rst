============
Future Plans
============

Registration
------------

- Look further into restricting the choice of certain usernames.
  Are groups in a namespace distinct from usernames?  It looks like not.
  Should reject username if::
     username in set(
         user for user, perm in PermissionSystem(env).get_all_permissions())

OpenID Extension Support
------------------------

- SREG: is the ``sreg_required`` really needed?  Can we just "require"
  everything, then use whatever comes back?

- The PAPE support needs work (I think)

- Set timezone and/or language/locale for new accounts from SREG/AX

User Interface
--------------

- Clean up the OpenID selector interface
  - Use `UI extension`_ (google)
    - Popup auth window
    - Favicon display
  - Do the redirect via AJAX to get rid of the blank auto-submit form page

- Optionally, put icons for authentication via providers that provide
  user-select in the metanav bar

- Admin interface for viewing/"adjusting" OpenID associations
  - trac-admin command(s)
  - web UI too

- Integration with TracAccountManager plugin
  - Make sure they work together
  - Integrate new account registration?
  - Integrate admin web UI?

.. _UI extension: http://svn.openid.net/repos/specifications/user_interface/1.0/trunk/openid-user-interface-extension-1_0.html

Testing
-------

- Coverage
- Get tests to run under MySQL, Postgres
- Test with unicode (usernames, names, etc...)
