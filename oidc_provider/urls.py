from django.urls import path
from django.views.decorators.csrf import csrf_exempt

from oidc_provider import (
    settings,
    views,
)

app_name = 'oidc_provider'
urlpatterns = [
    path('authorize/', views.AuthorizeView.as_view(), name='authorize'),
    path('token/', csrf_exempt(views.TokenView.as_view()), name='token'),
    path('userinfo/', csrf_exempt(views.userinfo), name='userinfo'),
    path('end-session/', views.EndSessionView.as_view(), name='end-session'),
    path('.well-known/openid-configuration/', views.ProviderInfoView.as_view(),
        name='provider-info'),
    path('introspect/', views.TokenIntrospectionView.as_view(), name='token-introspection'),
    path('jwks/', views.JwksView.as_view(), name='jwks'),
]

if settings.get('OIDC_SESSION_MANAGEMENT_ENABLE'):
    urlpatterns += [
        path('check-session-iframe/', views.CheckSessionIframeView.as_view(),
            name='check-session-iframe'),
    ]
