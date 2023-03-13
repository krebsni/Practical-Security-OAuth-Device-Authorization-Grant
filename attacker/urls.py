from django.urls import path
from . import views

app_name = "attacker"

urlpatterns = [
    path('device', views.user_code_entry, name='device'),
    path('device/<int:user_code>', views.verification_complete, name='device'),
    path('process-user-code', views.process_user_code, name="process_user_code"),
    path('authenticate', views.authenticate_ua, name='authenticate'),
    path('get-client-id', views.get_client_id, name='get-client-id'),
    path('authorization-endpoint', views.authorization_endpoint,
         name='authorization-endpoint'),
    path('token-endpoint', views.token_endpoint, name='token-endpoint'),
    path('denial-of-service-attack', views.denial_of_service_attack, name='dos'),
    path('csrf-with-qr-code', views.csrfqr, name='csrfqr'),
    path('leak-user-code', views.leak_user_code, name='leak-user-code'),
    path('leak-device-code', views.leak_device_code, name='leak-device-code'),
    path('remote-phishing', views.remote_phishing, name='rp'),
    path('remote-phishing-indirect', views.remote_phishing_indirect, name='rp-indirect'),
    path('brute-force-user-code', views.brute_force_user_code,
         name='brute-force-user-code'),
    path('brute-force-device-code', views.brute_force_device_code,
         name='brute-force-device-code'),
    path('ad', views.referer, name='ad'),
]
