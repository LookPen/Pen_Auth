#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File  : mixins.py
# @Author: Pen
# @Date  : 2017-11-23 09:59
# @Desc  :

import logging

from django.core.exceptions import ImproperlyConfigured
from django.views import View

from oauth_pen.exceptions import FatalClientError

log = logging.getLogger("oauth2_provider")


class OAuthMixin(View):
    server_class = None
    validator_class = None
    oauth_backend_class = None

    @classmethod
    def get_server_class(cls):
        if cls.server_class is None:
            raise ImproperlyConfigured(
                'OAuthMixin 的server_class为空,请定义server_class或重写get_server_class()')
        else:
            return cls.server_class

    @classmethod
    def get_validator_class(cls):
        if cls.validator_class is None:
            raise ImproperlyConfigured(
                'OAuthMixin 的validator_class为空,请定义validator_class或重写get_validator_class()')
        else:
            return cls.validator_class

    @classmethod
    def get_oauth_backend_class(cls):
        if cls.oauth_backend_class is None:
            raise ImproperlyConfigured(
                'OAuthMixin 的validator_class为空,请定义oauth_backend_class或重写get_oauth_backend_class()')
        else:
            return cls.oauth_backend_class

    @classmethod
    def get_server(cls):
        server_class = cls.get_server_class()
        validator_class = cls.get_validator_class()
        return server_class(validator_class())

    @classmethod
    def get_oauth_core(cls):
        """
        获取oauth 的核心实例,并缓存起来
        :return:
        """
        if not hasattr(cls, '_oauth_core'):
            server = cls.get_server()
            core_class = cls.get_oauth_backend_class()
            cls._oauth_core = core_class(server)
        return cls._oauth_core

    def validate_authorization_request(self, request):
        """

        :param request:
        :return:
        """
        core = self.get_oauth_core()
        return core.validate_authorization_request(request)

    def create_authorization_response(self, request, credentials, allow):
        """

        :param request:
        :param credentials:
        :param allow:
        :return:
        """
        core = self.get_oauth_core(request, credentials, allow)
        return core.get_oauth_core(request, credentials, allow)

    def create_token_response(self, request):
        """

        :param request:
        :return:
        """
        core = self.get_oauth_core()
        return core.create_token_response(request)

    def create_revocation_response(self, request):
        """

        :param request:
        :return:
        """
        core = self.get_oauthlib_core()
        return core.create_revocation_response(request)

    def verify_request(self, request):
        """

        :param request:
        :return:
        """
        core = self.get_oauthlib_core()
        return core.verify_request(request, scopes=self.get_scopes())

    def error_response(self, error, **kwargs):
        """

        :param error:
        :param kwargs:
        :return:
        """
        oauth_error = error.oauth_error

        redirect_uri = oauth_error.redirect_uri or ""
        separator = '&' if '?' in redirect_uri else '?'

        error_response = {
            'error': oauth_error,
            'url': "{0}{1}{2}".format(redirect_uri, separator, oauth_error.urlencoded)
        }
        error_response.update(kwargs)

        if isinstance(error, FatalClientError):
            redirect = False
        else:
            redirect = True

        return redirect, error_response
