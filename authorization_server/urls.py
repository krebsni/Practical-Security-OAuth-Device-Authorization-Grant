from django.urls import path

from . import views

app_name = "authorization_server"
urlpatterns = [
    path('device', views.user_code_entry, name='device'),
    path('device/<int:user_code>', views.verification_complete, name='device'),
    path('process-user-code', views.process_user_code, name="process-user-code"),
    path('authenticate', views.authenticate_ua, name='authenticate'),
    path('get-client-id', views.get_client_id, name='get-client-id'),
    path('authorization-endpoint', views.device_authorization_endpoint,
         name='authorization-endpoint'),
    path('token-endpoint', views.token_endpoint, name='token-endpoint'),
    path('find-client-id', views.find_client_id, name='find-client-id'),
]
