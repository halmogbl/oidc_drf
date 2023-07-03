import base64
import hashlib
import requests
import logging
import json
import jwt

from oidc_drf.utils import import_from_settings

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import ImproperlyConfigured, SuspiciousOperation
from django.utils.module_loading import import_string
from django.utils.encoding import force_bytes, smart_bytes, smart_str

from requests.auth import HTTPBasicAuth
from josepy.jws import JWS, Header
from josepy.b64 import b64decode
from josepy.jwk import JWK

from oidc_drf.models import OIDCExtraData
LOGGER = logging.getLogger(__name__)



def default_username_algo(email):
    """Generate username for the Django user.

    :arg str/unicode email: the email address to use to generate a username

    :returns: str/unicode

    """
    # bluntly stolen from django-browserid
    # store the username as a base64 encoded sha224 of the email address
    # this protects against data leakage because usernames are often
    # treated as public identifiers (so we can't use the email address).
    username = base64.urlsafe_b64encode(
        hashlib.sha1(force_bytes(email)).digest()
    ).rstrip(b"=")

    return smart_str(username)

class OIDCAuthenticationBackend(ModelBackend):

    def __init__(self, *args, **kwargs):
        """Initialize settings."""
        self.OIDC_OP_TOKEN_ENDPOINT = import_from_settings("OIDC_OP_TOKEN_ENDPOINT")
        self.OIDC_OP_USER_ENDPOINT = import_from_settings("OIDC_OP_USER_ENDPOINT")
        self.OIDC_OP_JWKS_ENDPOINT = import_from_settings("OIDC_OP_JWKS_ENDPOINT", None)
        self.OIDC_RP_CLIENT_ID = import_from_settings("OIDC_RP_CLIENT_ID")
        self.OIDC_RP_CLIENT_SECRET = import_from_settings("OIDC_RP_CLIENT_SECRET","")
        self.OIDC_RP_SIGN_ALGO = import_from_settings("OIDC_RP_SIGN_ALGO", "RS256")
        self.OIDC_RP_IDP_SIGN_KEY = import_from_settings("OIDC_RP_IDP_SIGN_KEY", None)

        if self.OIDC_RP_SIGN_ALGO.startswith("RS") and (
            self.OIDC_RP_IDP_SIGN_KEY is None and self.OIDC_OP_JWKS_ENDPOINT is None
        ):
            msg = "{} alg requires OIDC_RP_IDP_SIGN_KEY or OIDC_OP_JWKS_ENDPOINT to be configured."
            raise ImproperlyConfigured(msg.format(self.OIDC_RP_SIGN_ALGO))

        self.UserModel = get_user_model()

    def authenticate(self,request, **kwargs):          
        
        self.request = request
        if not self.request:
            return None


        state = self.request.GET.get("state")
        code = self.request.GET.get("code")
        nonce = kwargs.pop("nonce", None)
        code_verifier = kwargs.pop("code_verifier", None)
        


        if not code or not state:
            return None

        redirect_uri = import_from_settings(
            "OIDC_AUTHENTICATION_SSO_CALLBACK_URL", "http://localhost:3000/callback"
        )



        token_payload = {
            "client_id": self.OIDC_RP_CLIENT_ID,
            "client_secret": self.OIDC_RP_CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri":redirect_uri,
        }


        # Send code_verifier with token request if using PKCE
        if code_verifier is not None:
            token_payload.update({"code_verifier": code_verifier})

        # Get the token
        token_info = self.get_token(token_payload)
        id_token = token_info.get("id_token")
        refresh_token = token_info.get("refresh_token")
        access_token = token_info.get("access_token")
        
        
        # Validate the token
        payload = self.verify_token(id_token, nonce=nonce)
                
        if payload:
            self.store_tokens(access_token, id_token, refresh_token)
            try:
                return self.get_or_create_user(access_token, id_token, payload)
            except SuspiciousOperation as exc:
                LOGGER.warning("failed to get or create user: %s", exc)
                return None
        return None
        
        
    def get_userinfo(self, access_token, id_token, payload):
        """Return user details dictionary. The id_token and payload are not used in
        the default implementation, but may be used when overriding this method"""

        user_response = requests.get(
            self.OIDC_OP_USER_ENDPOINT,
            headers={"Authorization": "Bearer {0}".format(access_token)},
            verify=import_from_settings("OIDC_VERIFY_SSL", True),
            timeout=import_from_settings("OIDC_TIMEOUT", None),
            proxies=import_from_settings("OIDC_PROXY", None),
        )
        
  
        user_response.raise_for_status()
        return user_response.json()
    
    def verify_claims(self, claims):
        """Verify the provided claims to decide if authentication should be allowed."""

        # Verify claims required by default configuration
        scopes = import_from_settings("OIDC_RP_SCOPES", "openid email")
        if "email" in scopes.split():
            return "email" in claims

        LOGGER.warning(
            "Custom OIDC_RP_SCOPES defined. "
            "You need to override `verify_claims` for custom claims verification."
        )

        return True

    def describe_user_by_claims(self, claims):
        username_claim = import_from_settings("OIDC_USERNAME_CLAIM", "preferred_username")
        username = claims.get(str(username_claim))
        return "username {}".format(username)
    
    def filter_users_by_claims(self, claims):
        """Return all users matching the specified username."""

        username = self.get_username(claims)
        
        if not username:
            return self.UserModel.objects.none()
        return self.UserModel.objects.filter(username__iexact=username)
    
    def mapper(self,claims):
        user_fields = {}
        field_mapping = import_from_settings("OIDC_FIELD_MAPPING",{} )
        for field_name, claim_key in field_mapping.items():
            value = claims.get(claim_key)
            if field_name == "username":
                continue
            if value is not None:
                user_fields[field_name] = value
        return user_fields

    def update_user(self, user, claims):        
        
        user_fields = self.mapper(claims)

        for field, value in user_fields.items():
            setattr(user, field, value)

        user.save()

        """Update existing user with new claims, if necessary save, and return user"""
        return user

    def get_username(self, claims):
        """Generate username based on claims."""
        username_algo = import_from_settings("OIDC_USERNAME_ALGO", None)
        username_claim = import_from_settings("OIDC_USERNAME_CLAIM", "preferred_username")
        use_encoded_username = import_from_settings("OIDC_USE_ENCODED_USERNAME", None)

        if use_encoded_username:
            if username_algo:
                if isinstance(username_algo, str):
                    username_algo = import_string(username_algo)
                return username_algo(claims.get(str(username_claim)))

            default_username_algo =  default_username_algo(claims.get(str(username_claim)))
    
        return str(claims.get(str(username_claim)))
        
    def create_user(self, claims):

        """Return object for a newly created user account."""
        username = self.get_username(claims)        
        user_fields = self.mapper(claims)
        user = get_user_model().objects.create_user(username, **user_fields)

        return user
    
    
    def create_user_json(self,user_info_json, access_token, id_token):
        excluded_fields = [
            "exp", "iat", "auth_time", "jti", "iss", "aud", "sub", "typ",
            "azp", "nonce", "session_state", "at_hash", "acr","allowed-origins","realm_access","resource_access","scope","sid"
        ]

        decoded_access_token = jwt.decode(access_token, algorithms=[self.OIDC_RP_SIGN_ALGO], verify=False, options={"verify_signature": False})

        decoded_id_token = jwt.decode(id_token, algorithms=[self.OIDC_RP_SIGN_ALGO], verify=False, options={"verify_signature": False})


        # Create a single JSON object
        user_json = {**user_info_json, **decoded_access_token, **decoded_id_token}
        
        # Remove excluded fields from decoded id_token
        user_json = {key: value for key, value in user_json.items() if key not in excluded_fields}
        
        return user_json
    
    def save_user_data(self,user, user_json):
        # Serialize the remaining user_json
        user_data = json.dumps(user_json)

        # Check if the user's OIDCExtraData already exists
        try:
            oidc_extra_data = user.oidcextradata
            oidc_extra_data.data = user_data
            oidc_extra_data.save()
        except OIDCExtraData.DoesNotExist:
            # Create a new OIDCExtraData object for the user
            oidc_extra_data = OIDCExtraData.objects.create(user=user, data=user_data)


    
    def get_or_create_user(self, access_token, id_token, payload):
        """Returns a User instance if 1 user is found. Creates a user if not found
        and configured to do so. Returns nothing if multiple users are matched."""

        user_info = self.get_userinfo(access_token, id_token, payload)
        



        # email based filtering
        users = self.filter_users_by_claims(user_info)

        if len(users) == 1:
            user = self.update_user(users[0], user_info)
            
            if user_info and access_token and id_token:
                user_json = self.create_user_json(user_info, access_token, id_token)
                self.save_user_data(user, user_json)
            return user

        elif len(users) > 1:
            # In the rare case that two user accounts have the same email address,
            # bail. Randomly selecting one seems really wrong.
            msg = "Multiple users returned"
            raise SuspiciousOperation(msg)
        elif import_from_settings("OIDC_CREATE_USER", True):
            user = self.create_user(user_info)
            if user_info and access_token and id_token:
                user_json = self.create_user_json(user_info, access_token, id_token)
                self.save_user_data(user, user_json)
            return user
        else:
            LOGGER.debug(
                "Login failed: No user with %s found, and " "OIDC_CREATE_USER is False",
                self.describe_user_by_claims(user_info),
            )
            return None

    def retrieve_matching_jwk(self, token):
        """Get the signing key by exploring the JWKS endpoint of the OP."""
        response_jwks = requests.get(
            self.OIDC_OP_JWKS_ENDPOINT,
            verify=import_from_settings("OIDC_VERIFY_SSL", True),
            timeout=import_from_settings("OIDC_TIMEOUT", None),
            proxies=import_from_settings("OIDC_PROXY", None),
        )
        response_jwks.raise_for_status()
        jwks = response_jwks.json()

        # Compute the current header from the given token to find a match
        jws = JWS.from_compact(token)
        json_header = jws.signature.protected
        header = Header.json_loads(json_header)

        key = None
        for jwk in jwks["keys"]:
            if import_from_settings("OIDC_VERIFY_KID", True) and jwk[
                "kid"
            ] != smart_str(header.kid):
                continue
            if "alg" in jwk and jwk["alg"] != smart_str(header.alg):
                continue
            key = jwk
        if key is None:
            raise SuspiciousOperation("Could not find a valid JWKS.")
        return key

    def _verify_jws(self, payload, key):
        """Verify the given JWS payload with the given key and return the payload"""
        jws = JWS.from_compact(payload)

        try:
            alg = jws.signature.combined.alg.name
        except KeyError:
            msg = "No alg value found in header"
            raise SuspiciousOperation(msg)

        if alg != self.OIDC_RP_SIGN_ALGO:
            msg = (
                "The provider algorithm {!r} does not match the client's "
                "OIDC_RP_SIGN_ALGO.".format(alg)
            )
            raise SuspiciousOperation(msg)

        if isinstance(key, str):
            # Use smart_bytes here since the key string comes from settings.
            jwk = JWK.load(smart_bytes(key))
        else:
            # The key is a json returned from the IDP JWKS endpoint.
            jwk = JWK.from_json(key)

        if not jws.verify(jwk):
            msg = "JWS token verification failed."
            raise SuspiciousOperation(msg)

        return jws.payload
    
    def get_payload_data(self, token, key):
        """Helper method to get the payload of the JWT token."""
        if import_from_settings("OIDC_ALLOW_UNSECURED_JWT", False):
            header, payload_data, signature = token.split(b".")
            header = json.loads(smart_str(b64decode(header)))

            # If config allows unsecured JWTs check the header and return the decoded payload
            if "alg" in header and header["alg"] == "none":
                return b64decode(payload_data)

        # By default fallback to verify JWT signatures
        return self._verify_jws(token, key)
    
    def verify_token(self, token, **kwargs):
        """Validate the token signature."""
        nonce = kwargs.get("nonce")

        token = force_bytes(token)
        if self.OIDC_RP_SIGN_ALGO.startswith("RS"):
            if self.OIDC_RP_IDP_SIGN_KEY is not None:
                key = self.OIDC_RP_IDP_SIGN_KEY
            else:
                key = self.retrieve_matching_jwk(token)
        else:
            key = self.OIDC_RP_CLIENT_SECRET

        payload_data = self.get_payload_data(token, key)

        # The 'token' will always be a byte string since it's
        # the result of base64.urlsafe_b64decode().
        # The payload is always the result of base64.urlsafe_b64decode().
        # In Python 3 and 2, that's always a byte string.
        # In Python3.6, the json.loads() function can accept a byte string
        # as it will automagically decode it to a unicode string before
        # deserializing https://bugs.python.org/issue17909
        payload = json.loads(payload_data.decode("utf-8"))
        token_nonce = payload.get("nonce")

        if import_from_settings("OIDC_USE_NONCE", True) and nonce != token_nonce:
            msg = "JWT Nonce verification failed."
            raise SuspiciousOperation(msg)
        return payload
    
    def get_token(self, payload):
        """Return token object as a dictionary."""

        auth = None
        if import_from_settings("OIDC_TOKEN_USE_BASIC_AUTH", False):
            # When Basic auth is defined, create the Auth Header and remove secret from payload.
            user = payload.get("client_id")
            pw = payload.get("client_secret")

            auth = HTTPBasicAuth(user, pw)
            del payload["client_secret"]

        response = requests.post(self.OIDC_OP_TOKEN_ENDPOINT,
            data=payload,
            auth=auth,
            verify=import_from_settings("OIDC_VERIFY_SSL", True),
            timeout=import_from_settings("OIDC_TIMEOUT", None),
            proxies=import_from_settings("OIDC_PROXY", None),
        )
        response.raise_for_status()
        return response.json()
    
    def store_tokens(self, access_token, id_token, refresh_token):
        """Store OIDC tokens."""
        session = self.request.session
        session["oidc_access_token"] = access_token
        session["oidc_id_token"] = id_token
        session["oidc_refresh_token"] = refresh_token
            
