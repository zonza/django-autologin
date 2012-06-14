import logging

from django.contrib import auth
from django.conf import settings
from django.core.exceptions import PermissionDenied, ObjectDoesNotExist
from django.http import HttpResponseRedirect

from Crypto.PublicKey import RSA  # pylint: disable=F0401

from autologin import USER_KEY, DATETIME_KEY, SIG_KEY
from autologin.utils import generate_message

log = logging.getLogger(__name__)


class AutoLoginMiddleware(object):
    """Allow auto-login from external services by verifying the login
    request (via a signature) with public key encryption"""
    username = datetime = sig = None

    def verify_attempt(self):
        priv_key = RSA.importKey(settings.AUTOLOGIN_PRIVATE_KEY.strip('\n'))
        pub_key = priv_key.publickey()
        message = generate_message(self.username, self.datetime)
        verified = pub_key.verify(message, (long(self.sig),))
        if not verified:
            raise PermissionDenied

    def process_request(self, request):
        meta = request.GET
        self.username = meta.get(USER_KEY)
        self.datetime = meta.get(DATETIME_KEY)
        self.sig = meta.get(SIG_KEY)
        is_auto = meta.has_key(USER_KEY) and meta.has_key(SIG_KEY) and meta.has_key(DATETIME_KEY)
        if not request.user.is_authenticated() and is_auto:
            backend = 'autologin.backends.AutoLoginBackend'
            if backend not in settings.AUTHENTICATION_BACKENDS:
                log.debug('Prepending custom auto-login backend to the authentication backends')
                settings.AUTHENTICATION_BACKENDS = ((backend, ) + settings.AUTHENTICATION_BACKENDS)
            redirect = meta.get('next', settings.LOGIN_REDIRECT_URL)
            try:
                user = auth.authenticate(username=self.username)
                if not user:
                    raise PermissionDenied
                self.verify_attempt()
                auth.login(request, user)
                return HttpResponseRedirect(redirect)
            except (ObjectDoesNotExist, PermissionDenied) as exc:
                log.debug("Unable to auto-login user '%s': %r" % (self.username, exc))
