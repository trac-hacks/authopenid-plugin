# [components]
# trac.web.auth.* = disabled
# openidauth.* = enabled


import pkg_resources

from trac.core import *
from trac.util.datefmt import all_timezones, get_timezone
from trac.web.chrome import INavigationContributor, ITemplateProvider
from trac.web.main import IRequestHandler, IAuthenticator
from trac.util import escape, Markup

from genshi.builder import tag



import re
import time

from trac.util import hex_entropy, md5crypt
from openid.store.sqlstore import MySQLStore

from openid.oidutil import appendArgs
from openid.cryptutil import randomString
from openid.fetchers import setDefaultFetcher, Urllib2Fetcher
from openid import sreg



class AuthOpenIdPlugin(Component):
    implements(INavigationContributor, IRequestHandler, ITemplateProvider, IAuthenticator)

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
        return re.match('/(login|opeidprocess|logout)/?$', req.path_info)

    def process_request(self, req):
        if req.path_info.startswith('/openidlogin'):
            self._do_login(req)
        elif req.path_info.startswith('/opeidprocess'):
            self._do_process(req)
        elif req.path_info.startswith('/opeidverify'):
            self._do_verify(req)
        elif req.path_info.startswith('/openidlogout'):
            self._do_logout(req)
        self._redirect_back(req)

    # IRequestHandler methods
    def match_request(self, req):
        return req.path_info == '/helloworld'

    def process_request(self, req):
        return 'openidlogin_login.html', {
            'settings': {'session': req.session, 'session_id': req.session.sid},
            'timezones': all_timezones, 'timezone': get_timezone
        }, None
        #req.send_response(200)
        #req.send_header('Content-Type', 'text/plain')
        #req.end_headers()
        #req.write('Hello world!')


    # ITemplateProvider methods

    def get_htdocs_dirs(self):
        return []

    def get_templates_dirs(self):
        return [pkg_resources.resource_filename('helloworld', 'templates')]
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
#        openid_url = self.query.get('openid_identifier')
#        if not openid_url:
#            self.render('Enter an OpenID Identifier to verify.',
#                        css_class='error', form_contents=openid_url)
#            return
#
#        immediate = 'immediate' in self.query
#        use_sreg = 'use_sreg' in self.query
#
#        oidconsumer = self.getConsumer()
#        try:
#            request = oidconsumer.begin(openid_url)
#        except consumer.DiscoveryFailure, exc:
#            fetch_error_string = 'Error in discovery: %s' % (
#                cgi.escape(str(exc[0])))
#            self.render(fetch_error_string,
#                        css_class='error',
#                        form_contents=openid_url)
#        else:
#            if request is None:
#                msg = 'No OpenID services found for <code>%s</code>' % (
#                    cgi.escape(openid_url),)
#                self.render(msg, css_class='error', form_contents=openid_url)
#            else:
#                # Then, ask the library to begin the authorization.
#                # Here we find out the identity server that will verify the
#                # user's identity, and get a token that allows us to
#                # communicate securely with the identity server.
#                if use_sreg:
#                    self.requestRegistrationData(request)
#
#                trust_root = self.server.base_url
#                return_to = self.buildURL('process')
#                if request.shouldSendRedirect():
#                    redirect_url = request.redirectURL(
#                        trust_root, return_to, immediate=immediate)
#                    self.send_response(302)
#                    self.send_header('Location', redirect_url)
#                    self.writeUserHeader()
#                    self.end_headers()
#                else:
#                    form_html = request.formMarkup(
#                        trust_root, return_to,
#                        form_tag_attrs={'id':'openid_message'},
#                        immediate=immediate)
#
#                    self.autoSubmit(form_html, 'openid_message')
#
#
#
#
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
#    def _redirect_back(self, req):
#        """Redirect the user back to the URL she came from."""
#        referer = req.get_header('Referer')
#        if referer and not referer.startswith(req.base_url):
#            # only redirect to referer if it is from the same site
#            referer = None
#        req.redirect(referer or req.abs_href())
#
