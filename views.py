#pylint: disable=C0103
import logging
from datetime import datetime

from Crypto.PublicKey import RSA  # pylint: disable=F0401

from django.http import Http404, HttpResponseRedirect, QueryDict
from django.views.generic import View
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from autologin import USER_KEY, DATETIME_KEY, SIG_KEY
from autologin.utils import generate_message

log = logging.getLogger(__name__)


class AutoLoginView(View):

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
        services = settings.AUTOLOGIN_SERVICES
        if not service in services.keys():
            raise Http404("Auto login for service '%s' not configured" % service)
        username = request.user.username
        date = datetime.now().isoformat()
        query = QueryDict('').copy()
        query.update({
            USER_KEY: username,
            DATETIME_KEY: date,
            SIG_KEY: self.generate_signature(username, date),
        })
        redirect = services[service] + '?' +  query.urlencode()
        return HttpResponseRedirect(redirect)

