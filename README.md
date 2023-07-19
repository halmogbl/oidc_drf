# Overview

Django DRF OIDC Auth library Securely authenticate users using OIDC in Django DRF. 
It Supports Code Flow and Code Flow With PKCE. Easy integration with React Js or any front-end framework.

----
# Installation

Install using `pip`...

```bash
pip install oidc_drf
```

Add `'oidc_drf'` to your `INSTALLED_APPS` setting.

```python
INSTALLED_APPS = [
    ...
    'oidc_drf',
]
```


Configure the following settings in your Django project's settings module:

```python

OIDC_RP_CLIENT_ID = '' # required
OIDC_RP_CLIENT_SECRET = '' # optional if public client 
OIDC_OP_AUTHORIZATION_ENDPOINT = ''# required
OIDC_OP_TOKEN_ENDPOINT = ''# required
OIDC_OP_USER_ENDPOINT = '' # required
OIDC_OP_LOGOUT_ENDPOINT ='' # required

OIDC_AUTHENTICATION_SSO_CALLBACK_URL = '' # required - identity provider will redirect you to this url after login

# Django Rest Framework settings
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'oidc_drf.drf.OIDCAuthentication',  # This is important to be the first one 
    ],
}

# Authentication backends
AUTHENTICATION_BACKENDS = [
    'oidc_drf.backends.OIDCAuthenticationBackend',
]



```

Next, edit your urls.py and add the following:

```python

from django.urls import path, include

urlpatterns = [
    # ...
    path('oidc/', include('oidc_drf.urls')),
    # ...
]

```

finnaly run the migrations commands

```bash

python3 manage.py makemigrations
python3 manage.py migrate

```

That's it, we're done!

----
# EXTRA SETTINGS
those settings are optional and populated with default values.

```python

OIDC_USE_NONCE = True # defalut true
OIDC_USE_PKCE = True # defalut true

# For RS256 algorithm to work, you need to set either the OP signing key or the OP JWKS Endpoint.
OIDC_RP_IDP_SIGN_KEY = None # defalut None
OIDC_OP_JWKS_ENDPOINT = None # defalut None

OIDC_USERNAME_CLAIM = 'preferred_username' # defalut 'preferred_username'
OIDC_RP_SIGN_ALGO = 'HS256' # defalut HS256
OIDC_RP_SCOPES = 'openid email profile' # defalut openid 
OIDC_VERIFY_SSL = True # defalut True
OIDC_TIMEOUT = None # defalut None
OIDC_PROXY = None # defalut None
OIDC_USERNAME_ALGO = None # defalut None
OIDC_USE_ENCODED_USERNAME = None # defalut None
OIDC_CREATE_USER = True # defalut True, Enables or disables automatic user creation during authentication
OIDC_CHECK_USER_MODEL = True # defalut True, if it is set to false it can authenticated based on oidc without User
OIDC_VERIFY_KID = True # defalut True 
OIDC_ALLOW_UNSECURED_JWT = False # defalut False
OIDC_TOKEN_USE_BASIC_AUTH = False # defalut False
OIDC_USER_CREATED_IS_ACTIVE= True # defalut True created user by oidc is set to is_active True
OIDC_USER_CREATED_IS_SUPERUSER= False# defalut False  created user by oidc is set to is_superuser False

# you can map the info comming back from the IDP to user model
# defalut is {}
OIDC_FIELD_MAPPING = {
    'field_in_my_user_model': 'field_in_in_oidc',
    'first_name': 'given_name',
    'last_name': 'family_name',
}

OIDC_EXTRA_USER_FIELDS = {
    "is_active": True,
    "is_superuser": False,
    # Add more fields as needed
}
```
----
# Django Admin

To view the info or fields comming back from the IDP in order to do proper mapping for OIDC_FIELD_MAPPING, all the data saved under the user model as oidc extra data.

**Below**: *Screenshot from the django admin*

![Screenshot2][django_admin_2]
![Screenshot3][django_admin_3]
----
# REST APIs
The REST API to the OIDC DRF is described below.

## AUTH ENDPOINT

**Note**

If `OIDC_USE_PKCE` is set to `True`:

- You should add `code_challenge` and `code_challenge_method` parameters to the authentication endpoint.
- You should save the `code_verifier` in local storage because it will be needed in the callback and refresh endpoints.

If `OIDC_USE_NONCE` is set to `True`:

- You should add the `nonce` parameter to the authentication endpoint.
- You should save the `nonce` in local storage because it will be needed in the callback endpoint.

----
***To generate the `code_challenge` and `nonce`, refer to this JavaScript library: [oidc_pkce](https://github.com/halmogbl/oidc_pkce).***

----


Example request with parameters:
### Request

`GET /oidc/auth/`

    curl --location 'http://localhost:8000/oidc/auth?code_challenge=4qZTfBVpD5xkxUIw0srf5rVV5H418hr-xQJLAd4c2Ss&code_challenge_method=S256&nonce=cFYLOJXZ8CANDC1SdQbvfUobixJdgUIc'
### Response

    Status: 200 OK
    {
        "redirect_url": "http://127.0.0.1:8080/realms/mol/protocol/openid-connect/auth?response_type=code&client_id=mowaamah&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=openid+email&state=rhG5l83rwd81SytApbl7MzrTDBFRXqbo&nonce=cFYLOJXZ8CANDC1SdQbvfUobixJdgUIc&code_challenge=4qZTfBVpD5xkxUIw0srf5rVV5H418hr-xQJLAd4c2Ss0&code_challenge_method=S256"
    }
    
## CALLBACK ENDPOINT

**Note**

If `OIDC_USE_PKCE` is set to `True`:

- you should include the "code_verifier" parameter in the request body.

If `OIDC_USE_NONCE` is set to `True`:

- you should include the "nonce" parameter in the request body.

Remember to pass all the parameters returned from the 'OIDC_AUTHENTICATION_SSO_CALLBACK_URL', such as `state`, `session_state`, and `code`, to the callback endpoint.

Example request with parameters and request body:


### Request

`POST /oidc/callback/`

    curl --location 'http://localhost:8000/oidc/callback/?state=alksdfjlka&session_state=alsdjflajsdk&code=alsdjflaksdflkjls' \
    --header 'Content-Type: application/json' \
    --data '{
            "nonce": "cFYLOJXZ8CANDC1SdQbvfUobixJdgUIc",
            "code_verifier": "cNa9FYCujvVibPnosk1Fk3wvPPisaTjE8Ns83X0UcGsNlEfIUc3j49hFftYPEGAb"
    }'
### Response

    Status: 200 OK
    {
       "access":"jwt access token",
       "refresh":"jwt refresh token",
    }



## REFRESH ENDPOINT

**Note**

If `OIDC_USE_PKCE` is set to `True`:
- you should include the "code_verifier" parameter in the request body.
### Request

`POST /oidc/refresh/`

Example request with request body:

    curl --location 'http://localhost:8000/oidc/refresh/' \
    --header 'Content-Type: application/json' \
    --data '{
        "refresh": "jwt refresh token",
        "code_verifier": "cNa9FYCujvVibPnosk1Fk3wvPPisaTjE8Ns83X0UcGsNlEfIUc3j49hFftYPEGAb"
        }'
### Response

    Status: 200 OK
    {
       "access":"jwt access token",
       "refresh":"jwt refresh token",
    }


## LOGOUT ENDPOINT

### Request

`POST /oidc/logout/`

    curl --location 'http://localhost:8000/api/v1/oidc/logout' \
    --data '{"refresh": "jwt refresh token"}'

### Response

    Status: 200 OK
    {
        "message": "Logout OIDC Successful"
    }


[django_admin_1]: https://i.ibb.co/855dw0N/django-admin-1.png
[django_admin_2]: https://i.ibb.co/LdmfNky/django-admin-2.png
[django_admin_3]: https://i.ibb.co/J2rDkXS/django-admin-3.png


