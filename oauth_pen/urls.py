from django.conf.urls import url
from oauth_pen.views import views
from django.contrib.auth.views import login

urlpatterns = [
    url(r'^token/$', views.TokenView.as_view(), name="token"),
    url(r'^revoke_token/$', views.RevokeTokenView.as_view(), name="revoke-token"),
    url(r'^authorize/$', views.AuthorizationView.as_view(), name="authorize"),

    url(r'^login/$', views.LoginView.as_view(), name="login"),
]
