#!/usr/bin/python
#
# Copyright 2006 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Modifications by Stephen Paul Weber <http://singpolyma.net> released
# under the same license.

import cgi
import Cookie
import datetime
import logging
import os
import pickle
import sys
import traceback
import urlparse
import wsgiref.handlers
import hashlib
import random
import time
import urllib
import StringIO

from google.appengine.api import datastore
from google.appengine.api.datastore_types import Text
from google.appengine.ext import webapp
from google.appengine.ext.webapp import template
from google.appengine.api import mail

from openid.server import server as OpenIDServer
from openid.message import Message as OpenIDMessage
from openid.extensions.sreg import SRegRequest
from openid.extensions.sreg import SRegResponse
import store

# Set to True if stack traces should be shown in the browser, etc.
_DEBUG = True

# the global openid server instance
oidserver = None

def root_url():
  if os.environ.get('SERVER_SOFTWARE','').startswith('Devel'):
    return 'http://localhost:8080/'
  elif os.environ.get('SERVER_SOFTWARE','').startswith('Goog'):
    return 'http://email-verify.appspot.com/'
  else:
    logging.error('Unknown server. Production/development?')
    return 'wtf://error/'

def InitializeOpenId():
  global oidserver
  oidserver = OpenIDServer.Server(store.DatastoreStore(), root_url())

class Handler(webapp.RequestHandler):
  """A base handler class with a couple OpenID-specific utilities."""

  def __init__(self):
    super
    self.user = False
    self.oid_args = {}

  def ArgsToDict(self):
    """Converts the URL and POST parameters to a singly-valued dictionary.

    Returns:
      dict with the URL and POST body parameters
    """
    req = self.request
    d = dict([(arg, req.get(arg)) for arg in req.arguments()])
    d.update(self.oid_args)
    return d

  def HasCookie(self):
    """Returns True if we "remember" the user, False otherwise.

    Determines whether the user has used OpenID before and asked us to
    remember them - ie, if the user agent provided an 'openid_remembered'
    cookie.

    Returns:
      True if we remember the user, False otherwise.
    """
    cookies = os.environ.get('HTTP_COOKIE', None)
    if cookies:
      morsel = Cookie.BaseCookie(cookies).get('openid_remembered')
      if morsel and morsel.value == 'yes':
        return True

    return False

  def GetOpenIdRequest(self):
    """Creates and OpenIDRequest for this request, if appropriate.

    If this request is not an OpenID request, returns None. If an error occurs
    while parsing the arguments, returns False and shows the error page.

    Return:
      An OpenIDRequest, if this user request is an OpenID request. Otherwise
      False.
    """
    try:
      oidrequest = oidserver.decodeRequest(self.ArgsToDict())
      logging.debug('OpenID request: %s' % oidrequest)
      return oidrequest
    except:
      trace = ''.join(traceback.format_exception(*sys.exc_info()))
      self.ReportError('Error parsing OpenID request:\n%s' % trace)
      return False

  def Respond(self, oidresponse, sreg_req=False):
    """Send an OpenID response.

    Args:
      oidresponse: OpenIDResponse
      The response to send, usually created by OpenIDRequest.answer().
    """
    logging.warning('Respond: oidresponse.request.mode ' + oidresponse.request.mode)

    if sreg_req:
      sreg_resp = SRegResponse.extractResponse(sreg_req, {'email': self.user, 'nickname': self.user.rsplit('@',1)[0]})
      oidresponse.addExtension(sreg_resp)

    logging.debug('Using response: %s' % oidresponse)
    encoded_response = oidserver.encodeResponse(oidresponse)

    # update() would be nice, but wsgiref.headers.Headers doesn't implement it
    for header, value in encoded_response.headers.items():
      self.response.headers[header] = str(value)

    if encoded_response.code in (301, 302):
      self.redirect(self.response.headers['location'])
    else:
      self.response.set_status(encoded_response.code)

    if encoded_response.body:
      logging.debug('Sending response body: %s' % encoded_response.body)
      self.response.out.write(encoded_response.body)
    else:
      self.response.out.write('')

  def Render(self, template_name, extra_values={}):
    """Render the given template, including the extra (optional) values.

    Args:
      template_name: string
      The template to render.

      extra_values: dict
      Template values to provide to the template.
    """
    parsed = urlparse.urlparse(self.request.uri)
    request_url_without_path = parsed[0] + '://' + parsed[1]
    request_url_without_params = request_url_without_path + parsed[2]

    values = {
      'request': self.request,
      'request_url_without_path': request_url_without_path,
      'request_url_without_params': request_url_without_params,
      'user': self.user,
      'debug': self.request.get('deb'),
    }
    values.update(extra_values)
    cwd = os.path.dirname(__file__)
    path = os.path.join(cwd, 'templates', template_name + '.html')
    logging.debug(path)
    self.response.out.write(template.render(path, values, debug=_DEBUG))

  def ReportError(self, message):
    """Shows an error HTML page.

    Args:
      message: string
      A detailed error message.
    """
    args = pprint.pformat(self.ArgsToDict())
    self.Render('error', vars())
    logging.error(message)

  def store_login(self, oidrequest, kind):
    """Stores the details of an OpenID login in the datastore.

    Args:
      oidrequest: OpenIDRequest

      kind: string
      'remembered', 'confirmed', or 'declined'
    """
    assert kind in ['remembered', 'confirmed', 'declined']
    assert self.user

    login = datastore.Entity('Login')
    login['relying_party'] = oidrequest.trust_root
    login['time'] = datetime.datetime.now()
    login['kind'] = kind
    login['user'] = self.user
    datastore.Put(login)

  def CheckUser(self):
    """Checks that the OpenID identity being asserted is owned by this user.

    Specifically, checks that the request URI's path is the user's nickname.

    Returns:
      True if the request's path is the user's nickname. Otherwise, False, and
      prints an error page.
    """
    args = self.ArgsToDict()

    if not self.user:
      # not logged in!
      return False

    # check that the user is logging into their page, not someone else's.
    identity = args['openid.identity']
    parsed = urlparse.urlparse(identity)
    path = parsed[2]

    if urllib.unquote(path[4:]) != self.user:
      expected = parsed[0] + '://' + parsed[1] + '/id/' + self.user
      logging.warning('Bad identity URL %s for user %s; expected %s' %
                      (identity, self.user, expected))
      return False

    logging.debug('User %s matched identity %s' % (self.user, identity))
    return True

  def ShowFrontPage(self, error=False):
    """Do an internal (non-302) redirect to the front page.

    Preserves the user agent's requested URL.
    """
    front_page = FrontPage()
    front_page.request = self.request
    front_page.response = self.response
    front_page.get(error)


class FrontPage(Handler):
  """Show the default OpenID page, with the last 10 logins for this user."""
  def get(self, error=False):
    logins = []

    if self.user:
      query = datastore.Query('Login')
      query['user ='] = self.user
      query.Order(('time', datastore.Query.DESCENDING))
      logins = query.Get(10)

    self.Render('index', vars())


class Login(Handler):
  """Handles OpenID requests: associate, checkid_setup, checkid_immediate."""

  def get(self):
    """Handles GET requests."""

    oidrequest = self.GetOpenIdRequest()
    if oidrequest is False:
      # there was an error, and GetOpenIdRequest displayed it. bail out.
      return
    elif oidrequest is None:
      # this is a request from a browser
      self.ShowFrontPage()
    elif oidrequest.mode in ['checkid_immediate', 'checkid_setup']:
      if self.HasCookie() and self.CheckUser():
        logging.debug('Has cookie, confirming identity to ' +
                      oidrequest.trust_root)
        self.store_login(oidrequest, 'remembered')
        sreg_req = SRegRequest.fromOpenIDRequest(oidrequest)
        self.Respond(oidrequest.answer(True, root_url()), sreg_req)
      elif oidrequest.immediate:
        self.store_login(oidrequest, 'declined')
        oidresponse = oidrequest.answer(False)
        self.Respond(oidresponse)
      else:
        if self.CheckUser():
          self.Render('prompt', vars())
        else:
          email = urllib.unquote(urlparse.urlparse(self.request.uri)[2][4:])
          if not email:
            self.ReportError('Error, no email address specified.')
          else:
            if not '@' in email or not '.' in email:
              self.ReportError('Error, invalid email address specified.')
            else:
              v = datastore.Entity('Verification')
              v['token'] = hashlib.md5(email+str(random.random())+str(time.time())).hexdigest()
              v['email'] = email
              v['expires'] = int(time.time())+1800
              v['oidrequest'] = Text(pickle.dumps(self.ArgsToDict()))
              datastore.Put(v)
              mail.send_mail(sender="Email Verification <singpolyma@gmail.com>",
                    to=email,
                    subject="Please verify your email address",
                    body="""
You need to verify your email address to continue with your request to <%s>.

To continue, follow this link: <%slogin/%s>

or cut and paste the following verification code into the textbox back in your browser:

%s
""" % (oidrequest.trust_root, root_url(), v['token'], v['token']))
              self.Render('prompt', vars())

    elif oidrequest.mode in ['associate', 'check_authentication']:
      self.Respond(oidserver.handleRequest(oidrequest))

    else:
      self.ReportError('Unknown mode: %s' % oidrequest.mode)

  head = get
  post = get

  def prompt(self):
    """Ask the user to confirm an OpenID login request."""
    oidrequest = self.GetOpenIdRequest()
    if oidrequest:
      self.response.out.write(page)


class FinishLogin(Handler):
  """Handle a POST response to the OpenID login prompt form."""
  def post(self):

    token = self.request.get('token') or urlparse.urlparse(self.request.uri)[2].rsplit('/',2)[2]
    oid_args = False
    query = datastore.Query('Verification')
    query['token ='] = token
    v = query.Get(1)
    if v:
      v = v[0]
      if v['expires'] > time.time():
        self.user = v['email']
        self.oid_args = pickle.loads(str(v['oidrequest']))
      else:
        error = 'That token has expired.  Please try again.'
      datastore.Delete(v)
    else:
      error = 'No such token found.'

    if not self.CheckUser():
      self.ShowFrontPage(error)
      return

    args = self.ArgsToDict()

    try:
      oidrequest = OpenIDServer.CheckIDRequest.fromMessage(OpenIDMessage.fromPostArgs(args), '')
    except:
      trace = ''.join(traceback.format_exception(*sys.exc_info()))
      self.ReportError('Error decoding login request:\n%s' % trace)
      return

    if True: #args.has_key('yes'):
      logging.debug('Confirming identity to %s' % oidrequest.trust_root)
      if args.get('remember', '') == 'yes':
        logging.info('Setting cookie to remember openid login for two weeks')

        expires = datetime.datetime.now() + datetime.timedelta(weeks=2)
        expires_rfc822 = expires.strftime('%a, %d %b %Y %H:%M:%S +0000')
        self.response.headers.add_header(
          'Set-Cookie', 'openid_remembered=yes; expires=%s' % expires_rfc822)

      self.store_login(oidrequest, 'confirmed')
      sreg_req = SRegRequest.fromOpenIDRequest(oidrequest)
      self.Respond(oidrequest.answer(True, root_url()), sreg_req)

    elif args.has_key('no'):
      logging.debug('Login denied, sending cancel to %s' %
                    oidrequest.trust_root)
      self.store_login(oidrequest, 'declined')
      return self.Respond(oidrequest.answer(False))

    else:
      self.ReportError('Bad login request.')

  get = post

# Map URLs to our RequestHandler classes above
_URLS = [
  ('/', FrontPage),
  ('/login/?[^/]*', FinishLogin),
  ('/id/[^/]+', Login),
]

def main(argv):
  application = webapp.WSGIApplication(_URLS, debug=_DEBUG)
  InitializeOpenId()
  wsgiref.handlers.CGIHandler().run(application)

if __name__ == '__main__':
  main(sys.argv)
