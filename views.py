#pylint: disable=C0103
import logging

from Crypto.PublicKey import RSA  # pylint: disable=F0401

from django.views.generic import View
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from autologin.utils import generate_message, LoginRequestServer

log = logging.getLogger(__name__)


class AutoLoginView(View):
    """Capture the current user information and make an external login
    request to the appropriate service using a redirect"""

    def generate_signature(self, username, date):
        try:
            key = RSA.importKey(settings.AUTOLOGIN_PRIVATE_KEY.strip('\n'))
        except Exception, exc:
            msg = 'Problem with auto login key:', exc
            log.error(msg)
            raise ImproperlyConfigured(msg)
        message = generate_message(username, date)
        return str(key.sign(message, '')[0])

    def get(self, request, service, *args, **kwargs):
        request_server = LoginRequestServer(request.user.username, service)
        return request_server.generate_redirect()

