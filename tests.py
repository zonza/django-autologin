from datetime import datetime
import urlparse

from django.contrib.auth.models import User
from django.contrib.auth import logout
from django.conf import settings
from django.core.cache import cache
from django.http import QueryDict, HttpResponseRedirect
from django.test import TestCase

from mock import Mock, MagicMock  # pylint: disable=F0401

from autologin.utils import LoginRequestClient, LoginRequestServer
from autologin import USER_KEY, DATETIME_KEY, SIG_KEY

KEY = """
-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQDBOXSHoAQ6r/sRmMP7y5WJ8ASCR894tohUhu/oklLDuHyFp1XR
93srItFg/y6KW2X9KKSZrxfUIqflp9a1tUPu6uPytPn5zkRFx+QWgkF/Lk1Ui8Hf
IqwLjdnIprhIpmsEgc00DoUuoOHNIU6vqika+YKpkzQuqR7A7j07ids9gQIBIwKB
gQC7tCgOuLOmuZTPQ/GVg/BaHFwmyWp1Q5pgvZiYyKgr18lr5GH/Kuytj4mRbOth
1SE/EYn0YPKTj2FFfnjNxgd4r/wFi9Q4jQeJeGqSQxyGLr9kginlXoU+TVJFYtFG
FfQwOmN7BCUycZpwsmDj6vOYn0Y2I1FGrE4maX+Vel69QwJBAOiOLP/6EvNF1mdf
oaQW+3nxSR6R5duE68WMXEvX7lkbhh+GcFWpMB4qGxCdpA/JOzz/RAkZh1UVfZpi
hrW2dhsCQQDUtDh34aykK2HdB7EgnDXPh/bJE+eD+FCW0xXekHQJiNREScUWeXfC
ephoICD7Vg3rYMRlv3UqMUj2T9cwhwSTAkAak+fivX6CM939L4AwAqBltSztjQRT
mimS63hDLp7lnL7fCAzWlv4vVUTr9MJK8m0riuM0PW6NYYqyjurS8EgDAkA2sf/k
T/kxh3+Qm5PycU+qZMpuOFF5tOGF3oH3ZvlER8GN5xVsLdz3fpw4CEL+zPxD1w3u
RyzBtObgQGqI0kMBAkEAjcM1HWXSBspA4+jk6c5aAI7c0kG+Q88tQ5uME+chKbxQ
rfbKE7UP5n1yBhdeX+PPKOtNjKOsXCkg8utI3HtH6w==
-----END RSA PRIVATE KEY-----
"""

class TestSiteMetadataMapping(TestCase):

    def setUp(self):
        # Construct a mock request for each test
        cache.clear()
        self.request = Mock()
        self.user, __ = User.objects.get_or_create(username='admin')
        self.user.set_password('goose')
        self.user.save()
        self.request.user = self.user
        self.request.session = {}

    def testInvalidSig(self):
        "Test that an invalid signature is denied, preventing access"

        now = datetime(2011, 1, 1, 1, 12, 00, 100000)
        request = self.request.copy()
        request.GET = {
            USER_KEY: 'test-user',
            DATETIME_KEY: datetime(2011, 1, 1, 1, 12, 00, 100000).isoformat(),
            SIG_KEY: 11213123123,
        }
        request.user = self.user
        logout(request)
        login_request = LoginRequestClient(request, now, KEY)
        self.assertEqual(login_request.verify(), False)

    def testValidSig(self):
        "Test that a valid signature is validated successfully"

        # Construct login request server side
        domain = 'http://testserver/'
        settings.AUTOLOGIN_SERVICES = {'test': domain}
        now = datetime(2011, 1, 1, 1, 12, 00, 100000)
        request_server = LoginRequestServer(self.user.username, 'test', now, KEY)
        redirect = request_server.generate_redirect()
        querystring = urlparse.urlsplit(redirect['location']).query  # pylint: disable=E1103

        # Verify login request client side
        query = QueryDict(querystring)
        request = self.request.copy()
        request.GET = {
            USER_KEY: query.get(USER_KEY),
            DATETIME_KEY: query.get(DATETIME_KEY),
            SIG_KEY: query.get(SIG_KEY),
        }
        request.user = self.user
        session = MagicMock()
        session.flush = lambda: None
        request.session = session
        logout(request)
        self.assertFalse(request.user.is_authenticated())
        login_request = LoginRequestClient(request, now, KEY)
        redirect = login_request.verify()

        # Assert
        self.assertTrue(isinstance(redirect, HttpResponseRedirect))
        self.assertEqual(redirect['location'], settings.LOGIN_REDIRECT_URL)
        self.assertTrue(request.user.is_authenticated())
