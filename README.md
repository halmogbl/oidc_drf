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
OIDC_OP_JWKS_ENDPOINT = None # defalut None
OIDC_OP_AUTHORIZATION_ENDPOINT = ''# required
OIDC_OP_TOKEN_ENDPOINT = ''# required
OIDC_OP_USER_ENDPOINT = '' # required
OIDC_OP_LOGOUT_ENDPOINT ='' # required

OIDC_AUTHENTICATION_SSO_CALLBACK_URL = '' # required - identity provider will redirect you to this url after login
OIDC_LOGOUT_REDIRECT_URL = '' # required - identity provider will redirect you to this url after logout

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



# EXTRA SETTINGS
those settings are optional and populated with default values.

```python

OIDC_USE_NONCE = True # defalut true
OIDC_USE_PKCE = True # defalut true

OIDC_USERNAME_CLAIM = 'preferred_username' # defalut 'preferred_username'
OIDC_RP_SIGN_ALGO = 'RS256' # defalut RS256
OIDC_RP_SCOPES = 'openid email' # defalut openid email
OIDC_RP_IDP_SIGN_KEY = None # defalut None
OIDC_VERIFY_SSL = True # defalut True
OIDC_TIMEOUT = None # defalut None
OIDC_PROXY = None # defalut None
OIDC_USERNAME_ALGO = None # defalut None
OIDC_USE_ENCODED_USERNAME = None # defalut None
OIDC_CREATE_USER = True # defalut True
OIDC_VERIFY_KID = True # defalut True
OIDC_ALLOW_UNSECURED_JWT = False # defalut False
OIDC_TOKEN_USE_BASIC_AUTH = False # defalut False

# you can map the info comming back from IDP to user model
# defalut is {}
OIDC_FIELD_MAPPING = {
    'field_in_my_user_model': 'field_in_in_oidc',
    'first_name': 'given_name',
    'last_name': 'family_name',
}

```

# REST APIs
The REST API to the OIDC DRF is described below.

## AUTH ENDPOINT

### Request

`GET /oidc/auth/`

    curl --location 'http://localhost:8000/oidc/auth'
### Response

    Status: 200 OK
    {
        "redirect_url": "http://127.0.0.1:8080/realms/mol/protocol/openid-connect/auth?response_type=code&client_id=mowaamah&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=openid+email&state=rhG5l83rwd81SytApbl7MzrTDBFRXqbo&nonce=Pgsq3IlSLumPca81YjXc8ut03Oz7bPHA&code_challenge=OcDWjPAEzNI-mzrjSa2lKATcIH4oaXp7rpasc5CkRj0&code_challenge_method=S256",
        "oidc_states": {
            "nonce": "Pgsq3IlSLumPca81YjXc8ut03Oz7bPHA",
            "code_verifier": "cNa9FYCujvVibPnosk1Fk3wvPPisaTjE8Ns83X0UcGsNlEfIUc3j49hFftYPEGAb"
        }
    }
    
## CALLBACK ENDPOINT

### Request

`POST /oidc/callback/`

    curl --location 'http://localhost:8000/oidc/callback/?state=alksdfjlka&session_state=alsdjflajsdk&code=alsdjflaksdflkjls' \
    --header 'Content-Type: application/json' \
    --data '{
            "nonce": "Pgsq3IlSLumPca81YjXc8ut03Oz7bPHA",
            "code_verifier": "cNa9FYCujvVibPnosk1Fk3wvPPisaTjE8Ns83X0UcGsNlEfIUc3j49hFftYPEGAb"
    }'
### Response

    Status: 200 OK
    {
       "access":"jwt access token",
       "refresh":"jwt refresh token",
       "oidc_id_token":"jwt id token",
    }



## REFRESH ENDPOINT

### Request

`POST /oidc/refresh/`

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
       "oidc_id_token":"jwt id token",
    }


## LOGOUT ENDPOINT

### Request

`POST /oidc/logout/`

    curl --location 'http://localhost:8000/api/v1/oidc/logout' \
    --data '{"oidc_id_token": "jwt id token"}'

### Response

    Status: 200 OK
    {
        "message": "Logout OIDC successful"
    }






