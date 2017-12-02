from datetime import timezone

from django.db import models
from django.conf import settings

import Pen_Auth.constants as oc
from oauth_pen.generators import generate_client_id, generate_client_secret
from oauth_pen.validators import validate_uris


class User(models.Model):
    pass


class AbstractApplication(models.Model):
    CLIENT_CONFIDENTIAL = 'confidential'

    """
    认证服务器的一个客户端实例
    """
    client_id = models.CharField(max_length=100, unique=True, default=generate_client_id, db_index=True)
    redirect_uris = models.TextField(blank=True, validators=[validate_uris])  # 允许重定向的url
    client_type = models.CharField(max_length=32, default=oc.APPLICATION_CLIENT_TYPE[0])
    authorization_grant_type = models.CharField(max_length=32, choices=oc.APPLICATION_GRANT_TYPE[0])
    client_secret = models.CharField(max_length=255, blank=True, default=generate_client_secret, db_index=True)
    name = models.CharField(max_length=255, blank=True)
    skip_authorization = models.BooleanField(default=False)

    class Meta:
        abstract = True

    def __str__(self):
        return self.name or self.client_id


class Application(AbstractApplication):
    class Meta(AbstractApplication.Meta):
        swappable = 'OAUTH2_PROVIDER_APPLICATION_MODEL'


class AccessToken(models.Model):
    user = models.ForeignKey(User, blank=True, null=True, on_delete=models.CASCADE)
    application = models.ForeignKey(Application, on_delete=models.CASCADE)
    token = models.CharField(max_length=255, unique=True)
    expires = models.DateTimeField()

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
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=255, unique=True)
    application = models.ForeignKey(Application, on_delete=models.CASCADE)
    access_token = models.OneToOneField(AccessToken, related_name='refresh_token', on_delete=models.CASCADE)

    def __str__(self):
        return self.token
