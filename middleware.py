import logging

from autologin.utils import LoginRequestClient

log = logging.getLogger(__name__)


class AutoLoginMiddleware(object):
    """Allow auto-login from external services by verifying the login
    request (via a signature) with public key encryption"""

    def process_request(self, request):
        login_request = LoginRequestClient(request)
        redirect = login_request.verify()
        if redirect:
            return redirect
