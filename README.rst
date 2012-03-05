============================
OpenID Authentication Plugin
============================

Description
===========

This plugin allows to login to Trac using OpenID. Please, note that
this plugin works with Trac 0.11 version only. Later versions might
work as well but I personally will not support them since I don't use
Trac anymore myself.

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

2. There is `Debian package` for this plugin::

       sudo aptitude install trac-authopenid

3. You can clone git repository somewhere in your system::

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

.. _PyPI: http://pypi.python.org/pypi/TracAuthOpenId/
.. _Debian package: http://packages.qa.debian.org/t/trac-authopenid.html
.. _pip: http://www.pip-installer.org/

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

This plugin has number of configuration options. Examples are best way
to illustrate them.
(NB: some of this is out of date and needs to be updated)::

    [trac]
    # Check user IP address. IP addresses are masked because
    # in some cases user is behind internal proxy and last
    # number in IP address might vary. Disable check_auth_ip
    # if you are using IPv6. If you still want to have IPv6
    # support please contact me.
    check_auth_ip = true
    check_auth_ip_mask = 255.255.255.0
    # number of seconds until cookie will expire
    expires = 86400

    [openid]
    # In some cases company might have internal OpenID server that automatically
    # identifies user (e.g. windows SSPI). Also known as single sign-on.
    # default_openid = http://openid.ee
    # Require sreg data
    sreg_required = false
    # If you want username to be written as username_in_remote_system<openid_url> use:
    # combined_username = false
    # Default PAPE method to request from OpenID provider.
    # pape_method =
    # What is OpenID link.
    whatis = http://openid.net/what/
    # Sign-up link
    signup = http://openid.net/get
    # Gmail login button (default: true)
    # gmail = false
    # In some cases you might want allow users to login to different projects using
    # different OpenIDs. In that case don't use absolute trust root.
    absolute_trust_root = false

    # Remove http:// or https:// from URL that is used as username. (Default: false)
    strip_protocol = false

    # Remove trailing slash from URL that is user as username (Defaul: false)
    strip_trailing_slash = false

    # Expiration time acts as timeout. E.g. if expiration time is 24 hour and
    # you login again in those 24 times. Expiration time is extended for another
    # 24 hours. (Default: false)
    timeout = false

    # white and black lists.
    # E.g.: Allows all the people from Lithuania, Latvia or Estonia except delfi domain.
    # IMPORTANT: strip_protocol and strip_trailing_slash affects what openid will be given to white_list or black_list
    #white_list = *.lt, *.lv, *.ee
    #black_list = *.delfi.lt,*.delfi.lv,*.delfi.ee

    # In addition to white and black lists you can use external service
    # for allowing users into trac. To control that you must use check_list
    # and check_list_key option. It will generate URL:
    # check_list?check_list_key=openid&email=email
    # email will be attached only if available.
    # It expects JSON result in following format:
    # {"check_list_key": true}
    # IMPORTANT: this functionality uses simplejson which might not be available on your system by default.
    # Install it if you want to use this functionality.
    # IMPORTANT: strip_protocol and strip_trailing_slash affects what openid will be send to service
    # NOTE: You can specify check_list_username as well. In that case JSON service should return new
    # username as well. E.g. check_list_username=username. Expected result from JSON service is:
    # {"check_list_key": true, "username": "Peter"}
    # You can use this option to map your OpenIDs to internal username.
    #check_list = http://your.site.com/openidallow
    #check_list_key = check_list
    #check_list_username=
    #
    # You can add one custom openid provider:
    #custom_provider_name = test
    #custom_provider_label = Enter openidprovider username:
    #custom_provider_url = http://openidprovider/{username}
    #custom_provider_image = http://openidprovider/favicon.png


Authors
=======

This plugin was written by `Dalius Dobravolskas`_.
It is currently being maintained by `Jeff Dairiki`_.

.. _Jeff Dairiki: mailto:dairiki@dairiki.org
.. _Dalius Dobravolskas: mailto:dalius@sandbox.lt
