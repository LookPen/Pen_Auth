from django.conf.urls import url
from oauth_pen.views import views

urlpatterns = [
    url(r'^token/$', views.TokenView.as_view(), name="token"),
]
