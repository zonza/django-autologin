import logging
from datetime import datetime, timedelta
import dateutil.parser

from django.contrib import auth
from django.conf import settings
from django.core.exceptions import PermissionDenied, ObjectDoesNotExist, ImproperlyConfigured
from django.http import Http404, HttpResponseRedirect, QueryDict

from Crypto.PublicKey import RSA  # pylint: disable=F0401

from autologin import USER_KEY, DATETIME_KEY, SIG_KEY

log = logging.getLogger(__name__)


def generate_message(username, date):
    return str("%s:%s" % (username, date))


class LoginRequestClient(object):

    def _verify_attempt(self):
        """Use the shared public key and signature to verify the login request"""
        priv_key = RSA.importKey(self.key.strip('\n'))
        pub_key = priv_key.publickey()
        message = generate_message(self.username, self.datetime)
        verified = pub_key.verify(message, (long(self.signature),))
        if not verified:
            msg = 'autologin request denied because signature was not valid'
            log.debug(msg)
            raise PermissionDenied(msg)

    def _verify_time(self, login_date):
        """Ensure the request is received within a minute"""
        current_date = self.now
        not_future = login_date < current_date
        if not current_date <= login_date + timedelta(minutes=1) and not_future:
            msg = 'autologin request denied because timestamp is old'
            log.debug(msg)
            raise PermissionDenied(msg)

    def verify(self):
        if not self.request.user.is_authenticated() and self.is_auto:
            login_date = dateutil.parser.parse(self.datetime)
            try:
                self._verify_time(login_date)
                backend = 'autologin.backends.AutoLoginBackend'
                if backend not in settings.AUTHENTICATION_BACKENDS:
                    settings.AUTHENTICATION_BACKENDS = ((backend, ) + settings.AUTHENTICATION_BACKENDS)
                user = auth.authenticate(username=self.username)
                if not user:
                    raise PermissionDenied
                self._verify_attempt()
                auth.login(self.request, user)
                return HttpResponseRedirect(self.next)
            except (ObjectDoesNotExist, PermissionDenied) as exc:
                log.debug("Unable to auto-login user '%s': %r" % (self.username, exc))
        return False

    def __init__(self, request, now=None, key=None):
        meta = request.GET
        self.key = key or settings.AUTOLOGIN_PRIVATE_KEY
        self.request = request
        self.username = meta.get(USER_KEY)
        self.datetime = meta.get(DATETIME_KEY)
        self.signature = meta.get(SIG_KEY)
        self.now = now or datetime.now()
        self.next = meta.get('next', settings.LOGIN_REDIRECT_URL)
        self.is_auto = bool(self.username and self.datetime and self.signature)

class LoginRequestServer(object):

    def __init__(self, username, service, now=None, key=None):
        self.username = username
        self.service = service
        self.date = now or datetime.now()
        self.key = key or settings.AUTOLOGIN_PRIVATE_KEY

    def generate_signature(self, username, date):
        try:
            key = RSA.importKey(self.key.strip('\n'))
        except Exception, exc:
            msg = 'Problem with auto login key:', exc
            log.error(msg)
            raise ImproperlyConfigured(msg)
        message = generate_message(username, date)
        return str(key.sign(message, '')[0])

    def generate_redirect(self):
        services = settings.AUTOLOGIN_SERVICES
        if not self.service in services.keys():
            raise Http404("Auto login for service '%s' not configured" % self.service)
        query = QueryDict('').copy()
        query.update({
            USER_KEY: self.username,
            DATETIME_KEY: self.date.isoformat(),
            SIG_KEY: self.generate_signature(self.username, self.date.isoformat()),
        })
        redirect = services[self.service] + '?' +  query.urlencode()
        return HttpResponseRedirect(redirect)
