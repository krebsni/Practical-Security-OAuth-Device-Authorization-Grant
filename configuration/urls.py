from django.conf.urls import url
from .views import ATTACK_CHOICES
from django.urls import path

from . import views

app_name = "configuration"

urlpatterns = [
    path('', views.index, name='index'),
    path('config', views.config, name='config'),
    path('logger-frame', views.logger_frame, name='logger-frame'),
    path('get-log', views.get_log, name='get-log'),
    path('clean-log', views.clean_log, name='clean-log'),
    path('configuration-complete', views.config_complete,
         name='config-complete'),
    path('no-attack', views.no_attack, name='no-attack'),
    path('user-code-leak', views.ucl, name='ucl'),
    path('device-code-leak', views.dcl, name='dcl'),
    path('man-in-the-middle', views.mitm, name='mitm'),
    path('remote-phishing', views.rp, name='rp'),
    path('csrf-with-qr-code', views.csrfqr, name='csrfqr'),
    path('corrupted-device-client', views.cdc, name='cdc'),
    path('denial-of-service', views.dos, name='dos'),
]
