from hashlib import sha256
import josepy.b64
from django.core.exceptions import ImproperlyConfigured
from django.conf import settings
from urllib.request import parse_http_list, parse_keqv_list


def absolutify(request, path):
    """Return the absolute URL of a path."""
    return request.build_absolute_uri(path)

def parse_www_authenticate_header(header):
    """
    Convert a WWW-Authentication header into a dict that can be used
    in a JSON response.
    """
    items = parse_http_list(header)
    return parse_keqv_list(items)


def import_from_settings(attr, *args):
    """
    Load an attribute from the django settings.

    :raises:
        ImproperlyConfigured
    """
    try:
        if args:
            return getattr(settings, attr, args[0])
        return getattr(settings, attr)
    except AttributeError:
        raise ImproperlyConfigured("Setting {0} not found".format(attr))


def base64_url_encode(bytes_like_obj):
    """Return a URL-Safe, base64 encoded version of bytes_like_obj

    Implements base64urlencode as described in
    https://datatracker.ietf.org/doc/html/rfc7636#appendix-A
    """

    s = josepy.b64.b64encode(bytes_like_obj).decode("ascii")  # base64 encode
    # the josepy base64 encoder (strips '='s padding) automatically
    s = s.replace("+", "-")  # 62nd char of encoding
    s = s.replace("/", "_")  # 63rd char of encoding

    return s

def generate_code_challenge(code_verifier, method):
    """Return a code_challege, which proves knowledge of the code_verifier.
    The code challenge is generated according to method which must be one
    of the methods defined in https://datatracker.ietf.org/doc/html/rfc7636#section-4.2:
    - plain:
      code_challenge = code_verifier
    - S256:
      code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
    """

    if method == "plain":
        return code_verifier

    elif method == "S256":
        return base64_url_encode(sha256(code_verifier.encode("ascii")).digest())

    else:
        raise ValueError("code challenge method must be 'plain' or 'S256'.")
