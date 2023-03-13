from django.urls import path
from . import views

app_name = "device"

urlpatterns = [
    path('', views.index, name='index'),
    path('grant', views.grant, name='grant'),
    path('grant-successful', views.grant_successful, name='grant-successful'),
]
