=========
autologin
=========

:Info: Django inter-project automatic login
:Authors: Steven Challis <steven.challis@hogarthww.com>
:Requires: PyCrypto >= 2.4.1, Django >= 1.3

Installation and Usage
======================

**autologin** is a django app that enables automatic login from one Django project to another.
Login requests are made using a basic GET redirect request and is verified by the remote
application using public key signatures.

To configure the application you will need to add the following settings to the client project's
settings.py::

    AUTOLOGIN_PRIVATE_KEY = """
    -----BEGIN RSA PRIVATE KEY-----
    <your_key>
    -----END RSA PRIVATE KEY-----
    """

    MIDDLEWARE_CLASSES = [
        'django.contrib.sessions.middleware.SessionMiddleware',
        'django.middleware.common.CommonMiddleware',
        'django.contrib.auth.middleware.AuthenticationMiddleware',
        'autologin.middleware.AutoLoginMiddleware',
    ]


The third party project should be configured with the following settings::

    AUTOLOGIN_PRIVATE_KEY = """
    -----BEGIN RSA PRIVATE KEY-----
    <your_key>
    -----END RSA PRIVATE KEY-----
    """

    AUTOLOGIN_SERVICES = {
        'thirdparty': 'http://thirdparty/',
    }

`urls.py` should also be configured to point at::

    (r'^autologin/', include('autologin.urls')),

Any request to `autologin/<service>/` will attempt to login to the url configured for `<service>`.
