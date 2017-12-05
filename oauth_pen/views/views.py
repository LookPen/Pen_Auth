import oauthlib
from braces.views import CsrfExemptMixin
from django.http import HttpResponse
from django.views.generic import View

from oauth_pen.views.mixins import OAuthMixin

import oauth_pen.oauth2_validators as ov
import oauth_pen.oauth2_backends as ob


class TokenView(CsrfExemptMixin, OAuthMixin):
    """
    server_class/validator_class/oauth_backend_class 应该要做成可配置的TODO
    """

    server_class = oauthlib.oauth2.Server
    validator_class = ov.OAuth2Validator
    oauth_backend_class = ob.OAuthCore

    def post(self, request, *args, **kwargs):
        """
        token 生成
        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        url, headers, body, status = self.create_token_response(request)

        response = HttpResponse(content=body, status=status)

        for k, v in headers.items():
            response[k] = v
        return response
