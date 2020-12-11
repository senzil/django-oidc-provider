from django.contrib.auth import views as auth_views
try: from django.urls import include, url
except ImportError: from django.conf.urls import include, url
from django.contrib import admin
from django.views.generic import TemplateView


urlpatterns = [
    url(r'^$', TemplateView.as_view(template_name='home.html'), name='home'),
    url(r'^admin/login/$', auth_views.LoginView.as_view(template_name='admin/login.html'), name='login'),
    url(r'^admin/logout/$', auth_views.LogoutView.as_view(template_name='admin/logout.html'), name='logout'),
    url(r'^openid/', include('oidc_provider.urls', namespace='oidc_provider')),
    url(r'^admin/', admin.site.urls),
]
