python setup.py sdist bdist_wheel
pip install twine
twine check dist/*
twine upload dist/*


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

# OIDC settings
OIDC_USE_NONCE = True #defalut true
OIDC_USE_PKCE = True #defalut true

OIDC_RP_SIGN_ALGO = 'RS256'
OIDC_RP_SCOPES = 'openid email'

OIDC_RP_CLIENT_ID = '' 
OIDC_RP_CLIENT_SECRET = '' 
OIDC_OP_JWKS_ENDPOINT = ''
OIDC_OP_AUTHORIZATION_ENDPOINT = ''
OIDC_OP_TOKEN_ENDPOINT = ''
OIDC_OP_USER_ENDPOINT = ''
OIDC_OP_LOGOUT_ENDPOINT =''

#identity provider will redirect you to this url after login
OIDC_AUTHENTICATION_SSO_CALLBACK_URL = '' 

# identity provider will redirect you to this url after logout
OIDC_LOGOUT_REDIRECT_URL = '' 

# you can map the info comming back from IDP to user model
OIDC_FIELD_MAPPING = {
    'field_in_my_user_model': 'field_in_in_oidc',
    'first_name': 'given_name',
    'last_name': 'family_name',
}

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



python3 manage.py makemigrations
python3 manage.py migrate

```

That's it, we're done!







# REST API

The REST API to the example app is described below.

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
       "access":"jwt token",
       "refresh":"jwt token"
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
       "refresh":"jwt refresh token"
    }


## LOGOUT ENDPOINT

### Request

`GET /oidc/logout/`

    curl --location 'http://localhost:8000/api/v1/oidc/logout' \
    --header 'Authorization: Bearer jwt access token'

### Response

    Status: 200 OK
    {
        "message": "Logout OIDC successful"
    }






