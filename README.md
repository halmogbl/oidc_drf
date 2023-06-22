python setup.py sdist bdist_wheel
pip install twine
twine check dist/*
twine upload dist/*

# OIDC Library

## Installation

Install the OIDC Library using pip:

```bash
pip install my-oidc-auth


Add `'oidc_drf'` to the `INSTALLED_APPS` list in your Django project's settings:

╰─ python manage.py makemigrations
╰─ python manage.py migrate

Configure the following settings in your Django project's settings module:

```python
# OIDC settings
OIDC_RP_CLIENT_SECRET = ''
OIDC_OP_JWKS_ENDPOINT = ''
OIDC_OP_AUTHORIZATION_ENDPOINT = ''
OIDC_OP_TOKEN_ENDPOINT = ''
OIDC_OP_USER_ENDPOINT = ''
OIDC_OP_LOGOUT_ENDPOINT = ''

OIDC_AUTHENTICATION_SSO_CALLBACK_URL = 'http://localhost:3000/callback'
OIDC_LOGOUT_REDIRECT_URL = 'http://localhost:3000'

# example mapping
OIDC_FIELD_MAPPING = {
    # "name_in_my_user_model":"name_in_oidc"
    'email': 'email',
    'first_name': 'given_name',
    'last_name': 'family_name',
}

# Django Rest Framework settings
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'oidc_drf.drf.CustomOIDCAuthentication',  # This is important to be the first one
    ],
}

# Authentication backends
AUTHENTICATION_BACKENDS = [
    'oidc_drf.backends.OIDCAuthenticationBackend',
]



Add routing to urls.py
Next, edit your urls.py and add the following:

from django.urls import path, include

urlpatterns = [
    # ...
    path('oidc/', include('oidc_drf.views.urls')),
    # ...
]
