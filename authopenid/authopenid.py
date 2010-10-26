# -*- coding: utf-8 -*-
#
# Copyright (C) 2007 Dalius Dobravolskas <dalius@sandbox.lt>
# All rights reserved.
#
# This software is licensed using the same licence as Trac:
# http://trac.edgewall.org/wiki/TracLicense.
#
# Author: Dalius Dobravolskas <dalius@sandbox.lt>
#
# Most probably you will want to add following lines to your configuration file:
#
#   [components]
#   trac.web.auth.* = disabled
#   authopenid.* = enabled

import pkg_resources
import cgi
import cPickle
import re
import time

from trac.core import *
from trac.config import Option, BoolOption, IntOption
from trac.web.chrome import INavigationContributor, ITemplateProvider, add_stylesheet, add_script
from trac.env import IEnvironmentSetupParticipant
from trac.web.main import IRequestHandler, IAuthenticator
from trac.web.session import DetachedSession
try:
    from acct_mgr.web_ui import LoginModule
except ImportError:
    from trac.web.auth import LoginModule

from genshi.builder import tag

from trac.util import hex_entropy
from openid.store.sqlstore import MySQLStore, PostgreSQLStore, SQLiteStore
from openid.store.memstore import MemoryStore

from openid.consumer import consumer
from openid.extensions import sreg, pape, ax

from openid import oidutil

import socket
import struct
import urllib

try:
    import simplejson # Necessary only for check_list option. Because of that it might be not installed by default
except ImportError:
    pass

class OpenIdLogger:
    """ Log all OpenID messages to debug. """

    def __init__(self, env):
        self.env = env

    def __call__(self, message, level=0):
        self.env.log.debug(message)

class AuthOpenIdPlugin(Component):

    openid_session_key = 'openid_session_data'
    openid_session_identity_url_key = 'openid_session_identity_url_data'

    implements(INavigationContributor, IRequestHandler, ITemplateProvider, IAuthenticator, IEnvironmentSetupParticipant)

    connection_uri = Option('trac', 'database', 'sqlite:db/trac.db',
        """Database connection
        [wiki:TracEnvironment#DatabaseConnectionStrings string] for this
        project""")

    check_ip = BoolOption('trac', 'check_auth_ip', 'true',
         """Whether the IP address of the user should be checked for
         authentication (''since 0.9'').""")
    check_ip_mask = Option('trac', 'check_auth_ip_mask', '255.255.255.0',
            """What mask should be applied to user address.""")

    trac_auth_expires = IntOption('trac', 'expires', 60*60*24,
            """Specify how fast authentication expires.""")

    timeout = BoolOption('openid', 'timeout', False,
            """Specify if expiration time should act as timeout.""")

    default_openid = Option('openid', 'default_openid', None,
            """Default OpenID provider for directed identity.""")

    strip_protocol = BoolOption('openid', 'strip_protocol', False,
            """Instead of using username beginning with http:// or https:// you can strip the beginning.""")

    strip_trailing_slash = BoolOption('openid', 'strip_trailing_slash', False,
            """In case your OpenID is some sub-domain address OpenId library adds trailing slash. This option strips it.""")

    sreg_required = BoolOption('openid', 'sreg_required', 'false',
            """Whether SREG data should be required or optional.""")

    combined_username = BoolOption('openid', 'combined_username', False,
            """ Username will be written as username_in_remote_system <openid_url>. """)

    pape_method = Option('openid', 'pape_method', None,
            """Default PAPE method to request from OpenID provider.""")

    signup_link = Option('openid', 'signup', 'http://openid.net/get/',
            """Signup link""")

    whatis_link = Option('openid', 'whatis', 'http://openid.net/what/',
            """What is OpenId link.""")

    absolute_trust_root = BoolOption('openid', 'absolute_trust_root', 'true',
            """Whether we should use absolute trust root or by project.""")

    white_list = Option('openid', 'white_list', '',
            """Comma separated list of allowed OpenId addresses.""")

    black_list = Option('openid', 'black_list', '',
            """Comma separated list of denied OpenId addresses.""")

    check_list = Option('openid', 'check_list', None,
            """JSON service for openid check.""")

    check_list_key = Option('openid', 'check_list_key', 'check_list',
            """Key for openid Service.""")

    check_list_username = Option('openid', 'check_list_username', None,
            """Username for openid Service.""")

    custom_provider_name = Option('openid', 'custom_provider_name', None,
            """ Custom OpenId provider name. """)

    custom_provider_label = Option('openid', 'custom_provider_label', 'Enter your username',
            """ Custom OpenId provider label. """)

    custom_provider_url = Option('openid', 'custom_provider_url', '',
            """ Custom OpenId provider URL. E.g.: http://claimid.com/{username} """)

    custom_provider_image = Option('openid', 'custom_provider_image', '',
            """ Custom OpenId provider image. """)

    def _get_masked_address(self, address):
        if self.check_ip:
            mask = struct.unpack('>L', socket.inet_aton(self.check_ip_mask))[0]
            address = struct.unpack('>L', socket.inet_aton(address))[0]
            return socket.inet_ntoa(struct.pack('>L', address & mask))
        return address

    def generate_re_list(self, list_in_string):
        """ Generates list of compiled regular expressions from given comma-separated
            list in string. """
        generated_list = []
        if list_in_string:
            for item in list_in_string.split(','):
                item = item.replace('.', '\\.')
                item = item.replace('*', '.*')
                item = item.strip()
                generated_list.append(re.compile(item))
                self.env.log.debug("Item compiled: %s" % item)

        return generated_list

    def __init__(self):
        db = self.env.get_db_cnx()
        oidutil.log = OpenIdLogger(self.env)
        self.env.log.debug("Compiling white-list")
        self.re_white_list = self.generate_re_list(self.white_list)
        self.env.log.debug("Compiling black-list")
        self.re_black_list = self.generate_re_list(self.black_list)


    def _getStore(self, db):
        scheme, rest = self.connection_uri.split(':', 1)
        if scheme == 'mysql':
            return MySQLStore(db.cnx.cnx)
        elif scheme == 'postgres':
            return PostgreSQLStore(db.cnx.cnx)
        elif scheme == 'sqlite':
            return SQLiteStore(db.cnx.cnx)
        else:
            return MemoryStore()

    def _initStore(self, db):
        store = self._getStore(db)
        if type(store) is not MemoryStore:
            store.createTables()

    # IEnvironmentSetupParticipant methods

    def environment_created(self):
        db = self.env.get_db_cnx()
        self._initStore(db)
        db.commit()

    def environment_needs_upgrade(self, db):
        c = db.cursor()
        try:
            c.execute("SELECT count(*) FROM oid_associations")
            return False
        except Exception, e:
            db.rollback()
            return True

    def upgrade_environment(self, db):
        self._initStore(db)

    # IAuthenticator methods

    def authenticate(self, req):
        authname = None
        if req.remote_user:
            authname = req.remote_user
            self.env.log.debug('authenticate. remote_user: %s' % authname)
        elif req.incookie.has_key('trac_auth'):
            authname = self._get_name_for_cookie(req, req.incookie['trac_auth'])
            self.env.log.debug('authenticate. cookie: %s' % authname)

        if not authname:
            self.env.log.debug('No OpenId authenticated user.')
            return None

        authname = authname.lower()

        return authname

    # INavigationContributor methods
    def get_active_navigation_item(self, req):
        return 'openidlogin'

    def get_navigation_items(self, req):
        if req.authname and req.authname != 'anonymous':
            if not self.env.is_component_enabled(LoginModule):
                yield ('metanav', 'openidlogin', 'logged in as %s' % (req.session.get('name') or req.authname))
                yield ('metanav', 'openidlogout',
                       tag.a('Logout', href=req.href.openidlogout()))
        else:
            yield ('metanav', 'openidlogin', tag.a(('OpenID Login'), href=req.href.openidlogin()))

    # IRequestHandler methods

    def match_request(self, req):
        return re.match('/(openidlogin|openidverify|openidprocess|openidlogout)\??.*', req.path_info)

    def process_request(self, req):
        if req.path_info.startswith('/openidlogin'):
            return self._do_login(req)
        elif req.path_info.startswith('/openidverify'):
            return self._do_verify(req)
        elif req.path_info.startswith('/openidprocess'):
            return self._do_process(req)
        elif req.path_info.startswith('/openidlogout'):
            return self._do_logout(req)

    def _do_login(self, req):
        # check the referer
        referer = req.get_header('Referer')
        if referer and not (referer == req.base_url or referer.startswith(req.base_url.rstrip('/')+'/')):
            # only redirect to referer if it is from the same site
            referer = None
        if referer:
           req.session['oid.referer'] = referer
        if self.default_openid:
           req.args['openid_identifier'] = self.default_openid
           return self._do_verify(req)
        add_stylesheet(req, 'authopenid/css/openid.css')
        add_script(req, 'authopenid/js/openid-jquery.js')
        return 'openidlogin.html', {
            'images': req.href.chrome('authopenid/images') + '/',
            'action': req.href.openidverify(),
            'message': 'Login using OpenID.',
            'signup': self.signup_link,
            'whatis': self.whatis_link,
            'css_class': 'error',
            'custom_provider_name': self.custom_provider_name,
            'custom_provider_label': self.custom_provider_label,
            'custom_provider_url': self.custom_provider_url,
            'custom_provider_image': self.custom_provider_image,
            }, None

    def _get_session(self, req):
        """Returns a session dict that can store any kind of object."""
        try:
            return cPickle.loads(str(req.session[self.openid_session_key]))
        except KeyError:
            return {}

    def _get_trust_root(self, req):
        href = req.href()
        abs_href = self.env.abs_href()
        self.env.log.debug('_get_trust_root href: ' + href)
        self.env.log.debug('_get_trust_root abs_href: ' + abs_href)
        if href and abs_href.endswith(href):
            base_url = abs_href[:-len(href)]
        else:
            base_url = abs_href

        return base_url

    def _commit_session(self, session, req):
        req.session[self.openid_session_key] = str(cPickle.dumps(session))

    def _get_consumer(self, req, db):
        s = self._get_session(req)
        if 'id' not in s:
            s['id'] = req.session.sid
        store = self._getStore(db)

        return consumer.Consumer(s, store), s

    def _do_verify(self, req):
        """Process the form submission, initating OpenID verification.
        """

        # First, make sure that the user entered something
        openid_url = req.args.get('openid_identifier')
        add_stylesheet(req, 'authopenid/css/openid.css')
        add_script(req, 'authopenid/js/openid-jquery.js')

        if not openid_url:
            return 'openidlogin.html', {
                'images': req.href.chrome('authopenid/images') + '/',
                'action': req.href.openidverify(),
                'message': 'Enter an OpenID Identifier to verify.',
                'signup': self.signup_link,
                'whatis': self.whatis_link,
                'css_class': 'error',
                'custom_provider_name': self.custom_provider_name,
                'custom_provider_label': self.custom_provider_label,
                'custom_provider_url': self.custom_provider_url,
                'custom_provider_image': self.custom_provider_image,
                }, None

        immediate = 'immediate' in req.args

        db = self.env.get_db_cnx()
        oidconsumer, session = self._get_consumer(req, db)
        try:
            self.env.log.debug('beginning OpenID authentication.')
            request = oidconsumer.begin(openid_url)
        except consumer.DiscoveryFailure, exc:
            fetch_error_string = 'Error in discovery: %s' % (
                cgi.escape(str(exc[0])))
            return 'openidlogin.html', {
                'images': req.href.chrome('authopenid/images') + '/',
                'action': req.href.openidverify(),
                'message': fetch_error_string,
                'signup': self.signup_link,
                'whatis': self.whatis_link,
                'css_class': 'error',
                'custom_provider_name': self.custom_provider_name,
                'custom_provider_label': self.custom_provider_label,
                'custom_provider_url': self.custom_provider_url,
                'custom_provider_image': self.custom_provider_image,
                }, None
        else:
            if request is None:
                msg = 'No OpenID services found for <code>%s</code>' % (
                    cgi.escape(openid_url),)
                return 'openidlogin.html', {
                    'images': req.href.chrome('authopenid/images') + '/',
                   'action': req.href.openidverify(),
                   'message': msg,
                   'signup': self.signup_link,
                   'whatis': self.whatis_link,
                   'css_class': 'error',
                    'custom_provider_name': self.custom_provider_name,
                    'custom_provider_label': self.custom_provider_label,
                    'custom_provider_url': self.custom_provider_url,
                    'custom_provider_image': self.custom_provider_image,
                   }, None
            else:
                self._commit_session(session, req)
                # Then, ask the library to begin the authorization.
                # Here we find out the identity server that will verify the
                # user's identity, and get a token that allows us to
                # communicate securely with the identity server.

                requested_policies = []
                if self.pape_method:
                   requested_policies.append(self.pape_method)

                pape_method = req.args.get('pape_method')
                if pape_method:
                    requested_policies.append(pape_method)

                if requested_policies:
                    pape_request = pape.Request(requested_policies)
                    request.addExtension(pape_request)

                # Let the sreg policy be configurable 
                sreg_opt = []
                sreg_req = []
                sreg_fields = ['fullname', 'email']
                if self.sreg_required:
                    sreg_req = sreg_fields
                else:
                    sreg_opt = sreg_fields
                sreg_request = sreg.SRegRequest(optional=sreg_opt, required=sreg_req)
                request.addExtension(sreg_request)

                ax_request = ax.FetchRequest()
                attr_info = ax.AttrInfo('http://schema.openid.net/contact/email', required=True)
                ax_request.add(attr_info)
                request.addExtension(ax_request)

                trust_root = self._get_trust_root(req)
                if self.absolute_trust_root:
                    trust_root += '/'
                else:
                    trust_root += req.href()
                return_to = self._get_trust_root(req) + req.href.openidprocess()
                if request.shouldSendRedirect():
                    redirect_url = request.redirectURL(
                        trust_root, return_to, immediate=immediate)
                    self.env.log.debug('Redirecting to: %s' % redirect_url)
                    req.redirect(redirect_url)
                else:
                    form_html = request.formMarkup(
                        trust_root, return_to,
                        form_tag_attrs={'id':'openid_message'},
                        immediate=immediate)

                    return 'autosubmitform.html', {
                        'id': 'openid_message',
                        'form': form_html
                       }, None

    def _do_process(self, req):
        """Handle the redirect from the OpenID server.
        """
        db = self.env.get_db_cnx()
        oidconsumer, session = self._get_consumer(req, db)

        # Ask the library to check the response that the server sent
        # us.  Status is a code indicating the response type. info is
        # either None or a string containing more information about
        # the return type.
        info = oidconsumer.complete(req.args,req.args['openid.return_to'])

        css_class = 'error'
        if info.status == consumer.FAILURE and info.identity_url:
            # In the case of failure, if info is non-None, it is the
            # URL that we were verifying. We include it in the error
            # message to help the user figure out what happened.
            fmt = "Verification of %s failed: %s"
            message = fmt % (cgi.escape(info.identity_url),
                             info.message)
        elif info.status == consumer.SUCCESS:
            # Success means that the transaction completed without
            # error. If info is None, it means that the user cancelled
            # the verification.
            css_class = 'alert'

            # This is a successful verification attempt. If this
            # was a real application, we would do our login,
            # comment posting, etc. here.
            fmt = "You have successfully verified %s as your identity."
            message = fmt % (cgi.escape(info.identity_url),)
            remote_user = info.identity_url

            reg_info = None

            ax_response = ax.FetchResponse.fromSuccessResponse(info)
            if ax_response:
                ax_data = ax_response.getExtensionArgs()
                email = ax_data.get('value.ext0.1', '')
                if email:
                    reg_info = {'email': email, 'fullname': email.split('@', 1)[0].replace('.', ' ').title()}

            if not reg_info:
                response = sreg.SRegResponse.fromSuccessResponse(info)
                if response:
                    reg_info = response.getExtensionArgs()

            if self.strip_protocol:
                remote_user = remote_user[remote_user.find('://')+3:]
            if self.strip_trailing_slash and remote_user[-1] == '/':
                remote_user = remote_user[:-1]
            if info.endpoint.canonicalID:
                # You should authorize i-name users by their canonicalID,
                # rather than their more human-friendly identifiers.  That
                # way their account with you is not compromised if their
                # i-name registration expires and is bought by someone else.
                message += ("  This is an i-name, and its persistent ID is %s"
                            % (cgi.escape(info.endpoint.canonicalID),))
                remote_user = info.endpoint.canonicalID

            allowed = True
            if self.re_white_list:
                self.env.log.debug("Filtering REMOTE_USER '%s' through white-list." % remote_user)
                allowed = False
                for item in self.re_white_list:
                    if not allowed and item.match(remote_user):
                        allowed = True
                        self.env.log.debug("User white-listed.")
            if allowed and self.re_black_list:
                self.env.log.debug("Filtering REMOTE_USER '%s' through black-list." % remote_user)
                for item in self.re_black_list:
                    if item.match(remote_user):
                        allowed = False
                        self.env.log.debug("User black-listed.")

            if allowed and self.check_list:
                params = {self.check_list_key: remote_user}
                if reg_info and reg_info.has_key('email') and len(reg_info['email']) > 0:
                    params['email'] = reg_info['email']
                url = self.check_list + '?' + urllib.urlencode(params)
                self.env.log.debug('OpenID check list URL: %s' % url)
                result = simplejson.load(urllib.urlopen(url))
                if not result[self.check_list_key]:
                    allowed = False
                elif self.check_list_username:
                    new_user = result[self.check_list_username]
                    if new_user:
                        remote_user = new_user

            if allowed:
                cookie = hex_entropy()

                req.outcookie['trac_auth'] = cookie
                req.outcookie['trac_auth']['path'] = req.href()
                req.outcookie['trac_auth']['expires'] = self.trac_auth_expires

                req.session[self.openid_session_identity_url_key] = info.identity_url

                if reg_info and reg_info.has_key('fullname') and len(reg_info['fullname']) > 0:
                    req.session['name'] = reg_info['fullname']
                if reg_info and reg_info.has_key('email') and len(reg_info['email']) > 0:
                    req.session['email'] = reg_info['email']

                self._commit_session(session, req) 

                if self.combined_username and req.session['name']:
                    remote_user = '%s <%s>' % (req.session['name'], remote_user)
                else:
                    if req.session.has_key('name'):
                        remote_user = req.session['name']

                    # Check if we generated a colliding remote_user and make the user unique
                    collisions = 0
                    cremote_user = remote_user
                    while True:
                        ds = DetachedSession(self.env, remote_user)
                        if not ds.last_visit:
                            # New session
                            break
                        if not ds.has_key(self.openid_session_identity_url_key):
                            # Old session, without the identity url set
                            # Save the identity url then (bascially adopt the session)
                            ds[self.openid_session_identity_url_key] = info.identity_url
                            ds.save()
                            break
                        if ds[self.openid_session_identity_url_key] == info.identity_url:
                            # No collision
                            break
                        # We got us a collision
                        # Make the thing unique
                        collisions += 1
                        remote_user = "%s (%d)" % (cremote_user, collisions+1)

                req.authname = remote_user

                db = self.env.get_db_cnx()
                cursor = db.cursor()
                cursor.execute("INSERT INTO auth_cookie (cookie,name,ipnr,time) "
                               "VALUES (%s, %s, %s, %s)", (cookie, remote_user,
                               self._get_masked_address(req.remote_addr), int(time.time())))
                db.commit()

                req.redirect(req.session.get('oid.referer') or self.env.abs_href())
            else:
                message = 'You are not allowed here.'
        elif info.status == consumer.CANCEL:
            # cancelled
            message = 'Verification cancelled'
        elif info.status == consumer.SETUP_NEEDED:
            if info.setup_url:
                message = '<a href=%s>Setup needed</a>' % (
                    quoteattr(info.setup_url),)
            else:
                # This means auth didn't succeed, but you're welcome to try
                # non-immediate mode.
                message = 'Setup needed'
        else:
            # Either we don't understand the code or there is no
            # openid_url included with the error. Give a generic
            # failure message. The library should supply debug
            # information in a log.
            message = 'Verification failed.'

        self._commit_session(session, req)

        add_stylesheet(req, 'authopenid/css/openid.css')
        add_script(req, 'authopenid/js/openid-jquery.js')
        return 'openidlogin.html', {
            'images': req.href.chrome('authopenid/images') + '/',
            'action': req.href.openidverify(),
            'message': message,
            'signup': self.signup_link,
            'whatis': self.whatis_link,
            'css_class': css_class,
            'custom_provider_name': self.custom_provider_name,
            'custom_provider_label': self.custom_provider_label,
            'custom_provider_url': self.custom_provider_url,
            'custom_provider_image': self.custom_provider_image,
            }, None

   # ITemplateProvider methods

    def get_htdocs_dirs(self):
        return [('authopenid', pkg_resources.resource_filename(__name__, 'htdocs'))]

    def get_templates_dirs(self):
        return [pkg_resources.resource_filename(__name__, 'templates')]

    def _do_logout(self, req):
        """Log the user out.

        Simply deletes the corresponding record from the auth_cookie table.
        """
        if req.authname == 'anonymous':
            # Not logged in
            req.redirect(self.env.abs_href())

        # While deleting this cookie we also take the opportunity to delete
        # cookies older than trac_auth_expires
        db = self.env.get_db_cnx()
        cursor = db.cursor()
        cursor.execute("DELETE FROM auth_cookie WHERE name=%s OR time < %s",
                       (req.authname, int(time.time()) - self.trac_auth_expires))
        db.commit()
        self._expire_cookie(req)
        custom_redirect = self.config['metanav'].get('logout.redirect')
        if custom_redirect:
            if custom_redirect.startswith('/'):
                custom_redirect = req.href(custom_redirect)
            req.redirect(custom_redirect)
        req.redirect(self.env.abs_href())

    def _expire_cookie(self, req):
        """Instruct the user agent to drop the auth cookie by setting the
        "expires" property to a date in the past.
        """
        req.outcookie['trac_auth'] = ''
        req.outcookie['trac_auth']['path'] = req.href()
        req.outcookie['trac_auth']['expires'] = -10000
        self.env.log.debug('trac_auth cookie expired.')

    def _get_name_for_cookie(self, req, cookie):
        db = self.env.get_db_cnx()
        cursor = db.cursor()
        if self.check_ip:
            cursor.execute("SELECT name FROM auth_cookie "
                           "WHERE cookie=%s AND ipnr=%s",
                           (cookie.value, self._get_masked_address(req.remote_addr)))
        else:
            cursor.execute("SELECT name FROM auth_cookie WHERE cookie=%s",
                           (cookie.value,))
        row = cursor.fetchone()
        if not row:
            # The cookie is invalid but we don't expire it because it might
            # be generated by different trac authentication mechanism.
            return None
        elif self.timeout:
            cursor.execute("UPDATE auth_cookie SET time=%s "
                           "WHERE cookie=%s AND name=%s",
                           (int(time.time()), cookie.value, row[0]))
            req.outcookie['trac_auth'] = cookie.value
            req.outcookie['trac_auth']['path'] = req.href()
            req.outcookie['trac_auth']['expires'] = self.trac_auth_expires

        return row[0]
