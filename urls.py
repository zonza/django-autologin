#pylint: disable=E1120
from django.conf.urls.defaults import patterns, url
from django.contrib.auth.decorators import login_required

from autologin.views import AutoLoginView

urlpatterns = patterns('',
    url(r'^(?P<service>\w+)/$',
        login_required(AutoLoginView.as_view()),
        name='autologin_login'),
)
