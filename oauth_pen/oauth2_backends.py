from urllib.parse import urlparse, urlunparse

from oauthlib.common import urlencode, urlencoded, quote

import oauth_pen.exceptions as ex
from oauth_pen.setting import oauth2_settings


class OAuthCore:
    def __init__(self, server=None):
        self.server = server or oauth2_settings.OAUTH2_SERVER_CLASS(oauth2_settings.OAUTH2_VALIDATOR_CLASS())

    def _get_escaped_full_path(self, request):
        """
        获取安全的url
        :param request:
        :return:
        """
        parsed = list(urlparse(request.get_full_path()))

        unsafe = set(c for c in parsed[4]).difference(urlencoded)

        for c in unsafe:
            parsed[4] = parsed[4].replace(c, quote(c, safe=b''))

        return urlunparse(parsed)

    def _extract_headers(self, request):
        """
        获取request 头
        :param request:
        :return:
        """
        headers = request.META.copy()

        # 在common.to_unicode() 时转不了，那就把你们删了吧
        if 'wsgi.input' in headers:
            del headers['wsgi.input']
        if 'wsgi.errors' in headers:
            del headers['wsgi.errors']

        if 'HTTP_AUTHORIZATION' in headers:
            headers['Authorization'] = headers['HTTP_AUTHORIZATION']

        return headers

    def _extract_body(self, request):
        """
        提取request 中的body
        :param request:
        :return:
        """
        return request.POST.items()

    def _extract_params(self, request):
        """
        提取request 中的参数
        :param request:
        :return:
        """
        uri = self._get_escaped_full_path(request)
        http_method = request.method
        headers = self._extract_headers(request)
        body = urlencode(self._extract_body(request))
        return uri, http_method, body, headers

    def _get_extra_credentials(self, request):
        """
        额外的授权参数
        :param request:
        :return:
        """
        return {}

    def validate_authorization_request(self, request):
        uri, http_method, body, headers = self._extract_params(request)
        scopes, credentials = self.server.validate_authorization_request(uri, http_method=http_method, body=body,
                                                                         headers=headers)

        return scopes, credentials

    def create_authorization_response(self, request, scopes, credentials, allow):
        if not allow:
            raise ex.AccessDeniedError()

        credentials['user'] = request.user
        headers, body, status = self.server.create_authorization_response(uri=credentials['redirect_uri'],
                                                                          scopes=scopes, credentials=credentials)
        uri = headers.get("Location", None)

        return uri, headers, body, status

    def create_token_response(self, request):
        uri, http_method, body, headers = self._extract_params(request)
        extra_credentials = self._get_extra_credentials(request)

        headers, body, status = self.server.create_token_response(uri, http_method, body,
                                                                  headers, extra_credentials)
        uri = headers.get("Location", None)

        return uri, headers, body, status

    def create_revocation_response(self, request):
        uri, http_method, body, headers = self._extract_params(request)

        headers, body, status = self.server.create_revocation_response(
            uri, http_method, body, headers)
        uri = headers.get("Location", None)

        return uri, headers, body, status

    def verify_request(self, request, scopes):
        uri, http_method, body, headers = self._extract_params(request)

        valid, r = self.server.verify_request(uri, http_method, body, headers, scopes=scopes)
        return valid, r
