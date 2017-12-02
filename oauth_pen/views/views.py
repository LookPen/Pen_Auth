import oauthlib
from braces.views import CsrfExemptMixin
from django.views.generic import View
import oauth_pen.provider as op
from oauth_pen.views.mixins import OAuthMixin


class TokenView(CsrfExemptMixin, OAuthMixin, View):
    """
    server_class/validator_class/oauth_backend_class 应该要做成可配置的TODO
    """

    server_class = oauthlib.oauth2.Server
    validator_class = ''
    oauth_backend_class = ''
