#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File  : validators.py
# @Author: Pen
# @Date  : 2017-11-22 11:51
# @Desc  : 验证器
import base64
import re
import logging

from django.conf import settings
from django.core.exceptions import ValidationError, ObjectDoesNotExist
from django.core.validators import RegexValidator
from oauthlib.oauth2 import RequestValidator
from urllib.parse import urlsplit, unquote_plus

from oauth_pen.models import Application, AbstractApplication

log = logging.getLogger('pen_oauth')


class RedirectURIValidator(RegexValidator):
    def __init__(self, allowed_schemes):
        self.allowed_schemes = allowed_schemes

    def __call__(self, *args, **kwargs):
        try:
            super(RedirectURIValidator, self).__call__(*args, **kwargs)
        except ValidationError as e:
            value = args[0]

            if value:
                if len(value.split('#')) > 1:
                    raise ValidationError('回调地址不支持锚点')

                scheme, netloc, path, query, fragment = urlsplit(value)
                if scheme.lower() not in self.allowed_schemes:
                    raise ValidationError('不支持的协议')
            else:
                raise ValidationError()


class OAuth2Validator(RequestValidator):
    def _extract_basic_auth(self, request):
        """
        返回basic认证客户端传入的token
        :param request:
        :return:
        """

        auth = request.header.get('HTTP_AUTHORIZATION')

        if not auth:
            return None

        split_str = auth.split(' ', 1)
        if len(split_str) != 2:
            return None

        auth_type, auth_str = split_str

        if auth_type != 'Basic':
            return None

        return auth_str

    def _load_application(self, client_id, request):
        """
        返回 application实例
        如果 request.client 没有设置,就根据 client_id 查找application 实例
        :param client_id:
        :param request:
        :return:
        """
        try:
            request.client = request.client or Application.objects.get(client_id=client_id)

            if not request.client.is_usable(request):
                log.debug('{0} 不可用'.format(client_id))
                return None
            return request.client
        except ObjectDoesNotExist:
            log.debug('没有找到{0}的 application'.format(client_id))
            return None

    def _authenticate_basic_auth(self, request):
        """
        Basic 认证 client

        注意： 根据oauth2.0 协议, client_id 和 client_secret 要通过 application/x-www-form-urlencoded 方式传入
        :param request:
        :return:
        """

        auth_string = self._extract_basic_auth(request)
        if not auth_string:
            return False

        # 请求编码 默认utf-8
        try:
            encoding = request.encoding or settings.DEFAULT_CHARSET or 'utf-8'
        except:
            encoding = 'utf-8'

        # basic认证的token 解码
        try:
            auth_string_decode = base64.b64decode(auth_string)
        except:
            log.debug('basic认证失败： token base64 解码失败')
            return False

        try:
            auth_string_decode = auth_string_decode.decode(encoding)
        except UnicodeDecodeError:
            log.debug('basic认证失败： token base64 解码后 转换成 {0} 失败'.format(encoding))
            return False

        client_id, client_secret = map(unquote_plus, auth_string_decode.split(':', 1))

        if self._load_application(client_id, request) is None:
            log.debug('basic认证失败：{0} 的 application不存在'.format(client_id))
            return False
        elif request.client.client_id != client_id:
            log.debug('basic认证失败：错误的client_id')
            return False
        elif request.client.client_secret != client_secret:
            log.debug("basic认证失败：错误的client_secret")
            return False
        else:
            return True

    def _authenticate_request_body(self, request):
        """
        通过请求body 将 client_id 和 client_secret 传入,从而认证客户端 （并不推荐这样用，至少你还是base64加下密嘛～）
        :param request:
        :return:
        """
        try:
            client_id = request.client_id
            client_secret = request.client_secret
        except AttributeError:
            return False

        if self._load_application(client_id, request) is None:
            log.debug('basic认证失败：{0} 的 application不存在'.format(client_id))
            return False

        elif request.client.client_secret != client_secret:
            log.debug("basic认证失败：错误的client_secret")
            return False
        else:
            return True

    def client_authentication_required(self, request, *args, **kwargs):
        """
        client 是否需要认证
        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        if self._extract_basic_auth(request):
            return True

        try:
            if request.client_id and request.client_secret:
                return True
        except AttributeError:
            log.debug('没有提供 client_id 和 client_secret')
            pass

        self._load_application(request.client_id, request)

        if request.client:
            return request.client.client_type == AbstractApplication.CLIENT_CONFIDENTIAL  # public 类型的client 不需要认证

        return super(OAuth2Validator, self).client_authentication_required(request, *args, **kwargs)

    def authenticate_client(self, request, *args, **kwargs):
        """
        认证客户端 (client)

        1. 尝试 Basic 认证（推荐方式）
        2. 对于不支持basic 认证的客户端，允许讲客户凭证通过请求body 传入

        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        authenticated = self._authenticate_basic_auth(request)

        if not authenticated:
            authenticated = self._authenticate_request_body(request)
        return authenticated

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        pass

    def validate_user(self, username, password, client, request, *args, **kwargs):
        pass

    def validate_client_id(self, client_id, request, *args, **kwargs):
        pass

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        pass

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        pass

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        pass

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        pass

    def validate_silent_login(self, request):
        pass

    def get_id_token(self, token, token_handler, request):
        pass

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, *args, **kwargs):
        pass

    def validate_user_match(self, id_token_hint, scopes, claims, request):
        pass

    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        pass

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        pass

    def validate_bearer_token(self, token, scopes, request):
        pass

    def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        pass

    def revoke_token(self, token, token_type_hint, request, *args, **kwargs):
        pass

    def save_bearer_token(self, token, request, *args, **kwargs):
        pass

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        pass

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        pass

    def validate_silent_authorization(self, request):
        pass

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        pass

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        """
        当 client 认证没有通过时（confidential的类型没有通过认证 或者是 public类型的client）
        :param client_id:
        :param request:
        :param args:
        :param kwargs:
        :return:
        """

        if not self._load_application(client_id, request):
            return request.client.client_type != AbstractApplication.CLIENT_CONFIDENTIAL  # 如果是public类型的client
        return False


def validate_uris(value):
    v = RedirectURIValidator(allowed_schemes=["http", "https"])

    uris = value.split()
    if not uris:
        raise ValidationError("重定向地址不能为空")
    for uri in uris:
        v(uri)
