import oauthlib
from braces.views import CsrfExemptMixin, LoginRequiredMixin
from django.contrib.auth import login, REDIRECT_FIELD_NAME
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.utils import timezone
from django.views import View
from django.views.generic import FormView
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate

from oauth_pen.exceptions import OAuthPenError
from oauth_pen.forms import AllowForm, AccountForm
from oauth_pen.models import Application, User
from oauth_pen.views.mixins import OAuthMixin

import oauth_pen.oauth2_validators as ov
import oauth_pen.oauth2_backends as ob


class TokenView(CsrfExemptMixin, OAuthMixin):
    """
    生产token
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


class RevokeTokenView(CsrfExemptMixin, OAuthMixin):
    """
    销毁token
    """
    server_class = oauthlib.oauth2.Server
    validator_class = ov.OAuth2Validator
    oauth_backend_class = ob.OAuthCore

    def post(self, request, *args, **kwargs):
        url, headers, body, status = self.create_revocation_response(request)
        response = HttpResponse(content=body or '', status=status)

        for k, v in headers:
            response[k] = v
        return response


class BaseAuthorizationView(LoginRequiredMixin, OAuthMixin):
    """
    触发该模块流程如下：
    1.用户打开客户端
    2.客户端要求用户给予授权（向认证服务器发送 认证请求）
    3.认证服务器在认证了客户端后向客户端返回授权页面（让用户选择是否授权）

    该模块返回 让用户选择是否授权的页面
    """

    def dispatch(self, request, *args, **kwargs):
        self.oauth2_data = {}
        return super(BaseAuthorizationView, self).dispatch(request, *args, **kwargs)

    def error_response(self, error, **kwargs):
        """
        错误处理
        :param error:
        :param kwargs:
        :return:
        """
        redirect, error_response = super(BaseAuthorizationView, self).error_response(error, **kwargs)

        if redirect:
            return HttpResponseRedirect(error_response['url'])

        status = error_response['error'].status_code

        return self.render_to_response(error_response, status=status)  # TODO


class AuthorizationView(BaseAuthorizationView, FormView):
    template_name = 'authorize.html'
    form_class = AllowForm

    server_class = oauthlib.oauth2.Server
    validator_class = ov.OAuth2Validator
    oauth_backend_class = ob.OAuthCore

    def get_initial(self):
        initial_data = {
            'redirect_uri': self.oauth2_data.get('redirect_uri', None),
            'client_id': self.oauth2_data.get('client_id', None),
            'state': self.oauth2_data.get('state', None),
            'response_type': self.oauth2_data.get('response_type', None),
        }
        return initial_data

    def form_valid(self, form):
        try:
            credentials = {
                'client_id': form.cleaned_data.get('client_id'),
                'redirect_uri': form.cleaned_data.get('redirect_uri'),
                'response_type': form.cleaned_data.get('response_type'),
                'state': form.cleaned_data.get('state')
            }

            allow = form.cleaned_data.get('allow')
            uri, headers, body, status = self.create_authorization_response(request=self.request,
                                                                            credentials=credentials, allow=allow)

            self.success_url = uri

            return HttpResponseRedirect(self.success_url)

        except OAuthPenError as error:
            return self.error_response(error)

    def get(self, request, *args, **kwargs):
        try:
            scopes, credentials = self.validate_authorization_request(request)

            application = Application.objects.get(client_id=credentials['client_id'])
            kwargs['application'] = application
            kwargs['client_id'] = credentials['client_id']
            kwargs['redirect_uri'] = credentials['redirect_uri']
            kwargs['response_type'] = credentials['response_type']
            kwargs['state'] = credentials['state']

            self.oauth2_data = kwargs

            form = self.get_form(self.get_form_class())
            kwargs['form'] = form

            require_approval = request.GET.get('approval_prompt', 'force')

            if application.skip_authorization:
                uri, headers, body, status = self.create_authorization_response(
                    request=self.request, credentials=credentials, allow=True)
                return HttpResponseRedirect(uri)
            elif require_approval == 'auto':
                tokens = request.user.accesstoken_set.filter(application=kwargs['application'],
                                                             expires__gt=timezone.now()).all()
                for token in tokens:
                    if token.allow_scopes(scopes):
                        uri, headers, body, status = self.create_authorization_response(
                            request=self.request, credentials=credentials, allow=True)

                        return HttpResponseRedirect(uri)

            return self.render_to_response(self.get_context_data(**kwargs))

        except OAuthPenError as error:
            return self.error_response(error)


class LoginView(FormView):
    # TODO： 用户登录模块以后有时间在写  这里先暂时用系统自带的
    template_name = 'login.html'
    form_class = AccountForm

    def form_valid(self, form):

        username = form.cleaned_data.get('username')
        password = form.cleaned_data.get('password')

        user = authenticate(self.request, **{'username': username, 'password': password})

        # user = User.objects.get(name=username, password=password)

        if user:
            login(self.request, user=user)

            self.success_url = self.request.GET.get(REDIRECT_FIELD_NAME)

            return HttpResponseRedirect(self.success_url)
        else:
            return self.render_to_response(self.get_context_data())
