"""device_grant_sec_simulation URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.urls.conf import include

from device_grant_sec_simulation import views as views

urlpatterns = [
    path('', views.startpage),
    path('admin/', admin.site.urls),
    path('attacker/', include('attacker.urls'), name='attacker'),
    path('configuration/', include('configuration.urls'), name='configuration'),
    path('device/', include('device.urls'), name='device'),
    path('authorization-server/', include('authorization_server.urls'),
         name='authorization_server'),
]