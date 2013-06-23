============================
OpenID Authentication Plugin
============================

Description
===========

This plugin allows to login to Trac using OpenID.  I use it with Trac 0.12.
It was developed under Trac 0.11, so it should work there too.
Version 0.4 of this plugin runs under trac 1.0 (formerly 0.13), but
this configuration has not yet been extensively tested or used in
production.

Download & Source
=================

The source repository is on github__.
You may submit bug reports and pull requests there.

__ https://github.com/dairiki/authopenid-plugin/

There are several ways to install this plugin.

1. You can install directly from PyPI_ using ``easy_install`` or pip_::

       easy_install TracAuthOpenId

   or::

       pip install TracAuthOpenId

.. _PyPI: http://pypi.python.org/pypi/TracAuthOpenId/
.. _pip: http://www.pip-installer.org/

2. There is a `Debian package`_ for this plugin::

       sudo aptitude install trac-authopenid

.. _Debian package: http://packages.qa.debian.org/t/trac-authopenid.html

3. `Patrick Uiterwijk`_ has packaged__ this plugin for Fedora::

       yum install trac-authopenid-plugin

   Should you have questions regarding the Fedora packaging, please file
   them in the Fedora `bug tracker`_.

__ https://apps.fedoraproject.org/packages/trac-authopenid-plugin
.. _bug tracker: https://apps.fedoraproject.org/packages/trac-authopenid-plugin/bugs

4. You can clone git repository somewhere in your system::

       cd /your/3rdparty/src
       git clone git://github.com/dairiki/authopenid-plugin.git

   Then you should do following steps::

       cd authopenid-plugin
       python setup.py install

   Alternatively, if you use pip_, you can  install directly from the git
   repository::

       pip install git+git://github.com/dairiki/authopenid-plugin.git

For any of the above methods, if you want to do a system-wide
installation, you will have to do this with *root* permissions
(e.g. using ``su`` or ``sudo``).


How to enable
=============

::

    [components]
    trac.web.auth.* = disabled
    authopenid.* = enabled


You don't need to disable default authentication mechanism
(trac.web.auth.*) if you are using it. OpenID plugin does not conflict
with default authentication mechanism.

Options
=======

This plugin has number of configuration options.  Here is an excerpt
from an example config file which lists all available options::

    [openid]

    ################################################################
    # Provider selection

    # Single sign-on support
    #
    # If you want to support only a single OpenID provider and that
    # provider allows the users to select his account as part of its
    # authentication process, set default_openid to the OP identifier
    # of the provider.  Then clicking the _OpenID Login_ link will take
    # the user directly to the providers authentication interface,
    # bypassing the openid provider/identity selection dialog.
    #
    # E.g. to use google as your sole openid provider, use
    #default_openid = https://www.google.com/accounts/o8/id

    # (If you have set default_openid, the identity selection dialog is
    # not displayed, and the rest of the options in this section are moot.)

    # Explicit set of provider names to display.  Should be set to a comman
    # separated list of provider names.  Choices include:
    # google, yahoo, aol, openid, myopenid, livejournal, flickr, technorati,
    # wordpress, blogger, verisign, vidoop, claimid, as well as any
    # custom provider you may have configured (via custom_provider_name).
    # By default all known providers are listed.
    #providers = google, myopenid

    # Add a custom openid provider to the form
    # provider name
    #custom_provider_name = myprovider
    # label
    #custom_provider_label = Enter your username
    # identity template
    #custom_provider_url = http://myprovider.example.net/{username}
    # URL to image/icon
    #custom_provider_image = /static/icons/myprovider.png
    # image size (small or large)
    #custom_provider_size = small

    # What is OpenID link.
    whatis_link = http://openid.net/what/
    # Sign-up link
    signup_link = http://openid.net/get

    ################################################################
    # Authorization

    # Identity white and black lists
    #
    # IMPORTANT: strip_protocol and strip_trailing_slash (see below) affectswhat
    # openid will be given to white_list or black_list

    # white_list: If set, only identities matching this list will be accepted
    # E.g. to allow only google and myopenid provided identities, use
    #white_list = https://www.google.com/accounts/o8/id?id=*, http://*.myopenid.com/

    # black_list: If set, matching identities will not be accepted
    #black_list = http://spammer.myopenid.com/

    # Comma separated list of allowed users, using the email address
    # resolved via SREG or AX. Use in combination with trusted
    # identity patterns in white_list.
    #email_white_list = joe@example.com

    # In addition to white and black lists you can use external web
    # service for allowing users into trac. To control that you must
    # use check_list and check_list_key option. It will generate URL:
    #
    #     <check_list>?<check_list_key>=openid&email=email
    #
    # email will be attached only if available.
    #
    # It expects JSON result in following format:
    #
    #     {"<check_list_key>": true}
    #
    # Your check_list web app may also be used to map openid
    # identifiers to your own internal authnames (usernames). (See
    # check_list_username below.)
    #
    # IMPORTANT: strip_protocol and strip_trailing_slash affects what
    # openid will be send to service
    #
    # You can use this option to map your OpenIDs to internal username.
    #check_list = http://your.site.com/openidallow

    # The parameter name used both for passing the claimed identity
    # to the authorization app, as well as for returning the authorization
    # status.  Defaults to "check_list".
    #check_list_key = check_list

    # Expiration time acts as timeout. E.g. if expiration time is 24
    # hour and you login again in those 24 hours. Expiration time is
    # extended for another 24 hours. (Default: false)
    timeout = false

    ################################################################
    # OpenID protocol and extensions

    # Require sreg data
    sreg_required = false

    # Default PAPE method to request from OpenID provider.
    # pape_method =

    # In some cases you might want allow users to login to different
    # projects using different OpenIDs. In that case don't use
    # absolute trust root.
    absolute_trust_root = false


    # Use the OpenIDTeams extension to request user's group membership.
    # If a user is a member of any of the teams listed in this option,
    # the user will be added to the trac permission group(s) of the same
    # name.  (Set to to a comma-separated list.)
    #
    # NOTE: To use this option, the python-openid-teams package must be
    # installed.
    groups_to_request =

    ################################################################
    # Authname (trac SID) generation

    # Force authname to lowercase (default true)
    #lowercase_authname = true

    # Use SREG nickname as authname (default false)
    #use_nickname_as_authname = false

    # If you want username to be written as
    # "username_in_remote_system <openid_url>" use:
    #combined_username = true

    # Remove http:// or https:// from URL that is used as
    # username. (Default: false)
    strip_protocol = false

    # Remove trailing slash from URL that is user as username (Defaul: false)
    strip_trailing_slash = false

    # If you have an external authorization web app configured (via
    # check_list), you may also use that to map openid identifiers to
    # local usernames (authnames).   Set check_list_username to the name
    # of a parameter which will be used to return the authname.
    # E.g. if check_list_username=username, the expected JSON result from
    # the authorization service is
    #
    #     {"check_list": true, "username": "Peter"}
    #
    #check_list_username=

    # Normally, the authname is not trusted to uniquely identify the user.
    # (What if another user has already registered with the same username?)
    # By default, a small integer is appended to the authname to make it
    # unique.  To default this, you may set trust_authname to true.
    #
    # WARNING: Setting this can is many circumstances make identity theft
    # very easy.  Only set this if you understand what you are doing.
    #trust_authname = false


    # Authentication cookie controls.
    #
    # Note that these are in the [trac] config section.

    [trac]

    # Check user IP address. IP addresses are masked because
    # in some cases user is behind internal proxy and last
    # number in IP address might vary.
    # (Does not currently support IPv6.)
    check_auth_ip = true
    check_auth_ip_mask = 255.255.255.0

    # number of seconds until cookie will expire
    auth_cookie_lifetime = 86400


Authors
=======

This plugin was written by `Dalius Dobravolskas`_.
It is currently being maintained by `Jeff Dairiki`_.
Other contributors include: `Patrick Uiterwijk`_.

.. _Jeff Dairiki: mailto:dairiki@dairiki.org
.. _Dalius Dobravolskas: mailto:dalius@sandbox.lt
.. _Patrick Uiterwijk: https://github.com/puiterwijk
