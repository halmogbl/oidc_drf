import logging
from rest_framework import exceptions
from django.core.exceptions import  SuspiciousOperation
from django.utils.module_loading import import_string
from requests.exceptions import HTTPError
from django.conf import settings
from rest_framework import authentication, exceptions
from django.core.exceptions import ImproperlyConfigured, SuspiciousOperation
from oidc_drf.utils import import_from_settings,parse_www_authenticate_header
from oidc_drf.backends import OIDCAuthenticationBackend
from django.contrib.auth import get_backends

LOGGER = logging.getLogger(__name__)

def get_oidc_backend():
    """
    Get the Django auth backend that uses OIDC.
    """

    # allow the user to force which back backend to use. this is mostly
    # convenient if you want to use OIDC with DRF but don't want to configure
    # OIDC for the "normal" Django auth.
    backend_setting = import_from_settings("OIDC_DRF_AUTH_BACKEND", None)
    if backend_setting:
        backend = import_string(backend_setting)()
        if not isinstance(backend, OIDCAuthenticationBackend):
            msg = (
                "Class configured in OIDC_DRF_AUTH_BACKEND "
                "does not extend OIDCAuthenticationBackend!"
            )
            raise ImproperlyConfigured(msg)
        return backend

    # if the backend setting is not set, look through the list of configured
    # backends for one that is an OIDCAuthenticationBackend.
    backends = [b for b in get_backends() if isinstance(b, OIDCAuthenticationBackend)]

    if not backends:
        msg = (
            "No backends extending OIDCAuthenticationBackend found - "
            "add one to AUTHENTICATION_BACKENDS or set OIDC_DRF_AUTH_BACKEND!"
        )
        raise ImproperlyConfigured(msg)
    if len(backends) > 1:
        raise ImproperlyConfigured("More than one OIDCAuthenticationBackend found!")
    return backends[0]

class OIDCAuthentication(authentication.BaseAuthentication):

    def __init__(self, backend=None):
        self.backend = backend or get_oidc_backend()
        

    def authenticate(self, request):
        access_token = self.get_access_token(request)
        if not access_token:
            return None
        try:
            for auth_class in settings.REST_FRAMEWORK['DEFAULT_AUTHENTICATION_CLASSES']:
                auth_class_name = auth_class.split('.')[-1]
                if auth_class_name != self.__class__.__name__:
                    auth = import_string(auth_class)()
                    user = auth.authenticate(request)
                    if user is not None:
                        return user
        except:

            try:
                user = self.backend.get_or_create_user(access_token, None, None)
            except HTTPError as exc:
                resp = exc.response
                if resp.status_code == 401 and "www-authenticate" in resp.headers:
                    data = parse_www_authenticate_header(resp.headers["www-authenticate"])
                    raise exceptions.AuthenticationFailed(
                        data.get("error_description", "no error description in www-authenticate")
                    )
                else:
                    raise exceptions.AuthenticationFailed("Authentication failed with all authentication classes.")
            except SuspiciousOperation as exc:
                LOGGER.info("Login failed: %s", exc)
                raise exceptions.AuthenticationFailed("Login failed")

            if not user:
                msg = "Login failed: No user found for the given access token."
                raise exceptions.AuthenticationFailed(msg)
            return user, access_token
        

    def get_access_token(self, request):
        """
        Get the access token based on a request.

        Returns None if no authentication details were provided. Raises
        AuthenticationFailed if the token is incorrect.
        """
        header = authentication.get_authorization_header(request)
        if not header:
            return None
        header = header.decode(authentication.HTTP_HEADER_ENCODING)

        auth = header.split()

        if auth[0].lower() != "bearer":
            return None

        if len(auth) == 1:
            msg = 'Invalid "bearer" header: No credentials provided.'
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = (
                'Invalid "bearer" header: Credentials string should not contain spaces.'
            )
            raise exceptions.AuthenticationFailed(msg)

        return auth[1]