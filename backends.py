import logging

from django.contrib.auth.backends import ModelBackend
from django.contrib import auth

log = logging.getLogger(__name__)


class AutoLoginBackend(ModelBackend):
    """A backend that does not require a password to authenticate"""

    def clean_username(self, username):
        return username.lower()

    def authenticate(self, username):  # pylint: disable=W0221
        try:
            return auth.models.User.objects.get(username=self.clean_username(username))
        except auth.models.User.DoesNotExist:
            return None
