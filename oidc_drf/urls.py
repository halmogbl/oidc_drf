from django.urls import path
from oidc_drf.views import OIDCGenerateAuthenticationUrlView,OIDCAuthenticationCallbackView,OIDCRefreshTokenView,OIDCLogoutView

urlpatterns = [
    path("auth/", OIDCGenerateAuthenticationUrlView.as_view(), name="oidc_authentication"),
    path("callback/", OIDCAuthenticationCallbackView.as_view(), name="oidc_authentication_callback"),
    path("refresh/", OIDCRefreshTokenView.as_view(), name="oidc_refresh"),
    path("logout/", OIDCLogoutView.as_view(), name="logout"),
]
