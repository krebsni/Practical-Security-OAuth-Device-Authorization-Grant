from django.http import request
from django.http.response import HttpResponseRedirect
from django.shortcuts import render
from django.http import HttpResponse
from django.urls import reverse
import logging

logger = logging.getLogger(__name__)
app_name = "device_grant_sec_simulation"


def startpage(request):
    return render(request, 'startpage.html')
