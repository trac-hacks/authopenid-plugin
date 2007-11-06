# [components]
# trac.web.auth.* = disabled
# openidauth.* = enabled


import pkg_resources
import cgi

from trac.core import *
from trac.web.chrome import INavigationContributor, ITemplateProvider
from trac.env import IEnvironmentSetupParticipant
from trac.web.main import IRequestHandler, IAuthenticator
from trac.util import escape, Markup

from genshi.builder import tag

import re
import time

#from trac.util import hex_entropy, md5crypt
from openid.store.sqlstore import MySQLStore
from openid.store import memstore
#from openid.store import filestore

from openid.consumer import consumer
from openid import sreg




class AuthOpenIdPlugin(Component):
    implements(INavigationContributor, IRequestHandler, ITemplateProvider, IAuthenticator, IEnvironmentSetupParticipant)

    def __init__(self):
        db = self.env.get_db_cnx()
        self.store = self._getStore(db)

    def _getStore(self, db):
        #return memstore.MemoryStore()
        return MySQLStore(db)

    def _initStore(self, db):
        self._getStore(db).createTables()

    # IEnvironmentSetupParticipant methods

    def environment_created(self):
        db = self.env.get_db_cnx()
        self._initStore(db)
        db.commit()

    def environment_needs_upgrade(self, db):
        return False

    def upgrade_environment(self, db):
        self._initStore(db)

    # IAuthenticator methods

    def authenticate(self, req):
        authname = None
        if req.remote_user:
            authname = req.remote_user
        elif req.incookie.has_key('trac_auth'):
            authname = self._get_name_for_cookie(req, req.incookie['trac_auth'])

        if not authname:
            return None

        authname = authname.lower()

        return authname

    # INavigationContributor methods
    def get_active_navigation_item(self, req):
        return 'openidlogin'

    def get_navigation_items(self, req):

        if req.authname and req.authname != 'anonymous':
            yield ('metanav', 'openidlogin', 'logged in as %s' % req.authname)
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
        #self._redirect_back(req)

    def _do_login(self, req):
        return 'openidlogin.html', {
            'action': req.href.openidverify(),
            'message': 'Enter your OpenID URL',
            'css_class': 'error'
        }, None

    def _get_consumer(self, req):
        session = req.session
        session['id'] = req.session.sid
        return consumer.Consumer(session, self.store)

    def _request_registration_data(self, request):
        sreg_request = sreg.SRegRequest(
            required=['nickname'], optional=['fullname', 'email'])
        request.addExtension(sreg_request)

    def _do_verify(self, req):
        """Process the form submission, initating OpenID verification.
        """

        # First, make sure that the user entered something
        openid_url = req.args.get('openid_identifier')
        if not openid_url:
            return 'openidlogin.html', {
                'action': req.href.openidverify(),
                'message': 'Enter an OpenID Identifier to verify.',
                'css_class': 'error'
            }, None

        immediate = 'immediate' in req.args
        use_sreg = 'use_sreg' in req.args

        oidconsumer = self._get_consumer(req)
        try:
            print '1'+'*'*80
            print openid_url.encode('utf-8')
            request = oidconsumer.begin(openid_url.encode('utf-8'))
        except consumer.DiscoveryFailure, exc:
            fetch_error_string = 'Error in discovery: %s' % (
                cgi.escape(str(exc[0])))
            return 'openidlogin.html', {
                'action': req.href.openidverify(),
                'message': fetch_error_string,
                'css_class': 'error'
                }, None
        else:
            print '*'*80
            if request is None:
                msg = 'No OpenID services found for <code>%s</code>' % (
                    cgi.escape(openid_url),)
                return 'openidlogin.html', {
                   'action': req.href.openidverify(),
                   'message': msg,
                   'css_class': 'error'
                   }, None
            else:
                # Then, ask the library to begin the authorization.
                # Here we find out the identity server that will verify the
                # user's identity, and get a token that allows us to
                # communicate securely with the identity server.
                if use_sreg:
                    self._request_registration_data(request)

                trust_root = req.href.openidlogin() # FIXME: let think about this one
                return_to = req.href.openidprocess()
                if request.shouldSendRedirect():
                    redirect_url = request.redirectURL(
                        trust_root, return_to, immediate=immediate)
                    req.send_response(302)
                    req.send_header('Location', redirect_url)
                    req.end_headers()
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
        oidconsumer = self._get_consumer(req)

        # Ask the library to check the response that the server sent
        # us.  Status is a code indicating the response type. info is
        # either None or a string containing more information about
        # the return type.
        info = oidconsumer.complete(req.args)

        sreg_resp = None
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
            sreg_resp = sreg.SRegResponse.fromSuccessResponse(info)
            if info.endpoint.canonicalID:
                # You should authorize i-name users by their canonicalID,
                # rather than their more human-friendly identifiers.  That
                # way their account with you is not compromised if their
                # i-name registration expires and is bought by someone else.
                message += ("  This is an i-name, and its persistent ID is %s"
                            % (cgi.escape(info.endpoint.canonicalID),))
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

        return 'openidlogin.html', {
            'action': req.href.openidverify(),
            'message': message,
            'css_class': css_class
            }, None

   # ITemplateProvider methods

    def get_htdocs_dirs(self):
        return []

    def get_templates_dirs(self):
        return [pkg_resources.resource_filename('authopenid', 'templates')]
        #return [resource_filename(__name__, 'templates')]


#    # Internal methods
#
#    def _do_login(self, req):
#        """Log the remote user in. """
#        if not req.remote_user:
#            raise TracError(tag("Authentication information not available. "
#                                "Please refer to the ",
#                                tag.a('installation documentation',
#                                      title="Configuring Authentication",
#                                      href=req.href.wiki('TracInstall') +
#                                      "#ConfiguringAuthentication"), "."))
#        remote_user = req.remote_user
#        remote_user = remote_user.lower()
#
#        assert req.authname in ('anonymous', remote_user), \
#               'Already logged in as %s.' % req.authname
#
#        cookie = hex_entropy()
#        db = self.env.get_db_cnx()
#        cursor = db.cursor()
#        cursor.execute("INSERT INTO auth_cookie (cookie,name,ipnr,time) "
#                       "VALUES (%s, %s, %s, %s)", (cookie, remote_user,
#                       req.remote_addr, int(time.time())))
#        db.commit()
#
#        req.authname = remote_user
#        req.outcookie['trac_auth'] = cookie
#        req.outcookie['trac_auth']['path'] = req.href()
#
#    def _do_process(self, req):
#        pass
#
#    def _do_logout(self, req):
#        """Log the user out.
#
#        Simply deletes the corresponding record from the auth_cookie table.
#        """
#        if req.authname == 'anonymous':
#            # Not logged in
#            return
#
#        # While deleting this cookie we also take the opportunity to delete
#        # cookies older than 10 days
#        db = self.env.get_db_cnx()
#        cursor = db.cursor()
#        cursor.execute("DELETE FROM auth_cookie WHERE name=%s OR time < %s",
#                       (req.authname, int(time.time()) - 86400 * 10))
#        db.commit()
#        self._expire_cookie(req)
#        custom_redirect = self.config['metanav'].get('logout.redirect')
#        if custom_redirect:
#            if custom_redirect.startswith('/'):
#                custom_redirect = req.href(custom_redirect)
#            req.redirect(custom_redirect)
#
#    def _expire_cookie(self, req):
#        """Instruct the user agent to drop the auth cookie by setting the
#        "expires" property to a date in the past.
#        """
#        req.outcookie['trac_auth'] = ''
#        req.outcookie['trac_auth']['path'] = req.href()
#        req.outcookie['trac_auth']['expires'] = -10000
#
#    def _get_name_for_cookie(self, req, cookie):
#        db = self.env.get_db_cnx()
#        cursor = db.cursor()
#        cursor.execute("SELECT name FROM auth_cookie WHERE cookie=%s",
#                (cookie.value,))
#        row = cursor.fetchone()
#        if not row:
#            # The cookie is invalid (or has been purged from the database), so
#            # tell the user agent to drop it as it is invalid
#            self._expire_cookie(req)
#            return None
#
#        return row[0]
#
    def _redirect_back(self, req):
        """Redirect the user back to the URL she came from."""
        referer = req.get_header('Referer')
        if referer and not referer.startswith(req.base_url):
            # only redirect to referer if it is from the same site
            referer = None
        req.redirect(referer or req.abs_href())
