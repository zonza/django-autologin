import logging

from django.contrib.auth.backends import ModelBackend
from django.contrib import auth

log = logging.getLogger(__name__)


class AutoLoginBackend(ModelBackend):
    """This backend extends the djangosaml2 one to add vidispine
    user. It is added automatically by the
    saml_assertion_consumer_service view.
    """

    def clean_username(self, username):
        return username.lower()

    def authenticate(self, username):  # pylint: disable=W0221
        try:
            return auth.models.User.objects.get(username=self.clean_username(username))
        except auth.models.User.DoesNotExist:
            return None
