from datetime import timezone
from urllib.parse import urlparse, parse_qsl

from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.db import models

import oauth_pen.constants as oc
from Pen_Auth import settings
from oauth_pen.generators import generate_client_id, generate_client_secret
from oauth_pen.validators import validate_uris


class User(AbstractBaseUser):
    USERNAME_FIELD = 'name'
    objects = BaseUserManager()

    name = models.CharField(max_length=255, unique=True, blank=True)


class AbstractApplication(models.Model):
    """
    认证服务器的一个客户端实例
    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    client_id = models.CharField(max_length=100, unique=True, default=generate_client_id, db_index=True)
    redirect_uris = models.TextField(blank=True, validators=[validate_uris])  # 允许重定向的url
    client_type = models.CharField(max_length=32, default=oc.APPLICATION_CLIENT_TYPE[0])
    authorization_grant_type = models.CharField(max_length=32, default=oc.APPLICATION_GRANT_TYPE[0])
    client_secret = models.CharField(max_length=255, blank=True, default=generate_client_secret, db_index=True)
    name = models.CharField(max_length=255, blank=True)
    skip_authorization = models.BooleanField(default=False)
    is_usable = models.BooleanField(default=True)

    @property
    def default_redirect_uri(self):
        if self.redirect_uris:
            return self.redirect_uris.split().pop(0)
        else:
            raise ValueError('implicit、authorization_code 模式必须设置回调地址')

    def redirect_uri_allowed(self, uri):
        """
        检查回调地址是否可用
        :param uri:
        :return:
        """
        for allowed_uri in self.redirect_uris.split():
            parsed_allowed_uri = urlparse(allowed_uri)
            parsed_uri = urlparse(uri)

            if (parsed_allowed_uri.scheme == parsed_uri.scheme and
                        parsed_allowed_uri.netloc == parsed_uri.netloc and
                        parsed_allowed_uri.path == parsed_uri.path):

                aqs_set = set(parse_qsl(parsed_allowed_uri.query))
                uqs_set = set(parse_qsl(parsed_uri.query))

                if aqs_set.issubset(uqs_set):
                    return True

        return False

    class Meta:
        abstract = True

    def __str__(self):
        return self.name or self.client_id


class Application(AbstractApplication):
    class Meta(AbstractApplication.Meta):
        # swappable = 'OAUTH2_PROVIDER_APPLICATION_MODEL'
        pass


class AccessToken(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, blank=True, null=True, on_delete=models.CASCADE)
    application = models.ForeignKey(Application, on_delete=models.CASCADE)
    token = models.CharField(max_length=255, unique=True)
    expires = models.DateTimeField()

    def revoke(self):
        """
        销毁一个token
        """
        self.delete()

    def is_expired(self):
        """
        判断token 是否过期
        """
        if not self.expires:
            return True

        return timezone.now() >= self.expires

    def __str__(self):
        return self.token


class RefreshToken(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    token = models.CharField(max_length=255, unique=True)
    application = models.ForeignKey(Application, on_delete=models.CASCADE)
    access_token = models.OneToOneField(AccessToken, related_name='refresh_token', on_delete=models.CASCADE)

    def revoke(self):
        """
        销毁一个刷新token
        """
        AccessToken.objects.get(id=self.access_token.id).revoke()
        self.delete()

    def __str__(self):
        return self.token


class Grant(models.Model):
    """
    授权实例，用于交换token
    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    code = models.CharField(max_length=255, unique=True)
    application = models.ForeignKey(Application, on_delete=models.CASCADE)
    expires = models.DateTimeField()
    redirect_uri = models.CharField(max_length=255)
    state = models.TextField(blank=True)

    def is_expired(self):
        """
        检查code 是否过期
        """
        if not self.expires:
            return True

        return timezone.now() >= self.expires

    def redirect_uri_allowed(self, uri):
        """
        回调地址是否有效
        :param uri:
        :return:
        """
        return uri == self.redirect_uri
