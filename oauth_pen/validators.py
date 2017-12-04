#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File  : validators.py
# @Author: Pen
# @Date  : 2017-11-22 11:51
# @Desc  : 验证器
import base64
import re
import logging

from datetime import timedelta

from django.contrib.auth import authenticate
from django.utils import timezone
from django.conf import settings
from django.core.exceptions import ValidationError, ObjectDoesNotExist
from django.core.validators import RegexValidator
from oauthlib.oauth2 import RequestValidator
from urllib.parse import urlsplit, unquote_plus

import oauth_pen.models as om
import oauth_pen.constants as oc
from oauth_pen.setting import oauth2_settings

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
            request.client = request.client or om.Application.objects.get(client_id=client_id)

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

        self._load_application(request.client_id, request)

        if request.client:
            return request.client.client_type == om.AbstractApplication.CLIENT_CONFIDENTIAL  # public 类型的client 不需要认证

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

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, *args, **kwargs):
        """
        确保回调地址的有效性
        :param client_id:
        :param code:
        :param redirect_uri:
        :param client:
        :param args:
        :param kwargs:
        :return:
        """
        grant = om.Grant.objects.get(code=code, application=client)
        return grant.redirect_uri_allowed(redirect_uri)

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        return request.client.default_redirect_uri

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        """
        获取默认的授权范围  暂不实现 TODO
        :param client_id:
        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        pass

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        """
        获取授权范围  暂不实现 TODO
        :param refresh_token:
        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        pass

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        """
        让code(用于交换token的凭据) 失效
        :param client_id:
        :param code:
        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        grant = om.Grant.objects.get(code=code, application=request.client)
        grant.delete()

    def revoke_token(self, token, token_type_hint, request, *args, **kwargs):
        """
        销毁一个token
        :param token:
        :param token_type_hint:
        :param request:
        :param args:
        :param kwargs:
        :return:
        """

        if token_type_hint not in ['access_token', 'refresh_token']:
            token_type_hint = None

        token_types = {
            'access_token': om.AccessToken,
            'refresh_token': om.RefreshToken,
        }

        token_type = token_types.get(token_type_hint, om.AccessToken)

        token_type.objects.get(token=token).revoke()

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        """
        创建一个code
        :param client_id:
        :param code:
        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        expires = timezone.now() + timedelta(seconds=oauth2_settings.AUTHORIZATION_CODE_EXPIRE_SECONDS)

        om.Grant.objects.create(application=request.client,
                                user=request.user,
                                code=code['code'],
                                expires=expires,
                                redirect_uri=request.redirect_uri)

    def rotate_refresh_token(self, request):
        """
        刷新token 是否使用新的的token字符串
        """
        return oauth2_settings.ROTATE_REFRESH_TOKEN

    def _create_access_token(self, expires, request, token):
        """
        创建token
        :param expires:
        :param request:
        :param token:
        :return:
        """
        access_token = om.AccessToken(
            user=request.user,
            expires=expires,
            token=token['access_token'],
            application=request.client
        )
        access_token.save()
        return access_token

    def save_bearer_token(self, token, request, *args, **kwargs):
        """
        保存token
        :param token:
        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        expires = timezone.now() + timedelta(seconds=oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)

        refresh_token_code = token.get('refresh_token', None)

        if refresh_token_code:
            # 刷新操作
            refresh_token_instance = getattr(request, 'refresh_token_instance', None)

            if not isinstance(refresh_token_instance, om.RefreshToken) or not refresh_token_instance.access_token:
                raise AttributeError('request 的refresh_token_instance 不存在')

            if self.rotate_refresh_token(request):
                # 使用新的token 字符串
                try:
                    refresh_token_instance.revoke()
                except (om.AccessToken.DoesNotExist, om.RefreshToken.DoesNotExist):
                    pass
                else:
                    setattr(request, 'refresh_token_instance', None)

                access_token = self._create_access_token(expires, request, token)

                refresh_token = om.RefreshToken(
                    user=request.user,
                    token=refresh_token_code,
                    application=request.client,
                    access_token=access_token
                )
                refresh_token.save()
            else:
                # 保持老的token字符串
                access_token = om.AccessToken.objects.select_for_update().get(pk=refresh_token_instance.access_token.pk)
                access_token.user = request.user
                access_token.expires = expires
                access_token.token = token['access_token']
                access_token.application = request.client
                access_token.save()
        else:
            # 不需要刷新、直接添加token
            self._create_access_token(expires, request, token)

    def get_id_token(self, token, token_handler, request):
        """
        open id 连接流程  还未理解
        :param token:
        :param token_handler:
        :param request:
        :return:
        """
        pass

    def validate_bearer_token(self, token, scopes, request):
        """
        token 验证 并给request client、user、access_token
        :param token:
        :param scopes:
        :param request:
        :return:
        """
        if not token:
            return False
        try:
            access_token = om.AccessToken.objects.select_related("application", "user").get(token=token)
            if not access_token.is_expired():
                request.client = access_token.application
                request.user = access_token.user
                request.access_token = access_token
                return True
            return False
        except ObjectDoesNotExist:
            return False

    def validate_client_id(self, client_id, request, *args, **kwargs):
        """
        验证客户端ID 是否有效, 同时添加到request对象中
        :param client_id:
        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        if self._load_application(client_id, request):
            request.client_id = request.client.client_id
            return True

        return False

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        """
        验证 code 同时添加到request
        :param client_id:
        :param code:
        :param client:
        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        try:
            grant = om.Grant.objects.get(code=code, application=client)
            if not grant.is_expired():
                request.user = grant.user
                request.state = grant.state
                return True
            return False
        except om.Grant.DoesNotExist:
            return False

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        """
        验证  grant_type
        :param client_id:
        :param grant_type:
        :param client:
        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        return grant_type in oc.APPLICATION_GRANT_TYPE

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        """
        验证回调地址
        :param client_id:
        :param redirect_uri:
        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        return request.client.redirect_uri_allowed(redirect_uri)

    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        """
        验证刷新token 并设置 request refresh_token_instance、refresh_token
        :param refresh_token:
        :param client:
        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        try:
            rt = om.RefreshToken.objects.get(token=refresh_token)
            request.user = rt.user
            request.refresh_token = rt.token
            request.refresh_token_instance = rt
            return rt.application == client
        except ObjectDoesNotExist:
            return False

    def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        """
        请求类型验证
        :param client_id:
        :param response_type:
        :param client:
        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        return True  # 暂不实现TODO

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        """
        权限范围验证
        :param client_id:
        :param scopes:
        :param client:
        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        return True  # 暂不实现TODO

    def validate_silent_login(self, request):
        """
        静默授权
        :param request:
        :return:
        """
        return True  # 暂不实现TODO

    def validate_silent_authorization(self, request):
        """
        静默授权验证
        :param request:
        :return:
        """
        True  # 暂不实现TODO

    def validate_user(self, username, password, client, request, *args, **kwargs):
        """
        验证用户名密码
        :param username:
        :param password:
        :param client:
        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        u = authenticate(username=username, password=password)
        if u is not None and u.is_active:
            request.user = u
            return True
        return False

    def validate_user_match(self, id_token_hint, scopes, claims, request):
        """
        确保客户端提供的user 同session 中的匹配
        :param id_token_hint:
        :param scopes:
        :param claims:
        :param request:
        :return:
        """


def validate_uris(value):
    v = RedirectURIValidator(allowed_schemes=["http", "https"])

    uris = value.split()
    if not uris:
        raise ValidationError("重定向地址不能为空")
    for uri in uris:
        v(uri)
