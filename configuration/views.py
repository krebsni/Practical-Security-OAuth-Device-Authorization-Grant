import os
from django.db.utils import OperationalError
from django.http.response import HttpResponseForbidden, HttpResponseRedirect
from django.shortcuts import render
from django.http import HttpResponse
from django.urls import reverse
from django.views.decorators.clickjacking import xframe_options_sameorigin
import requests
from .models import config_object, reset_config_db
from .models import ATTACK_CHOICES, RP_CHOICES, UCL_CHOICES, DCL_CHOICES, MITM_CHOICES, CDC_CHOICES
from device.models import reset_device_db
from configuration.models import reset_config_db
from authorization_server.models import reset_AS_db
from attacker.models import reset_attacker_db
import logging

logger = logging.getLogger(__name__)


def reset_db():
    """Reset attacker, AS, and device databases"""
    reset_attacker_db()
    reset_AS_db()
    reset_device_db()

def index(request):
    """Configuration and logging frames, resets databases"""
    context = {'attack_choices': ATTACK_CHOICES,
               'description': 'Configuration of Attack Scenario'}
    return render(request, 'configuration/index.html', context)


@xframe_options_sameorigin
def config(request):
    reset_db()
    reset_config_db()
    """Attack scenario options"""
    context = {'attack_choices': ATTACK_CHOICES,
               'description': 'Configuration of Attack Scenario'}
    return render(request, 'configuration/config.html', context)


@xframe_options_sameorigin
def logger_frame(request):
    """Returns logger html-page"""
    return render(request, 'configuration/logger.html')


@xframe_options_sameorigin
def get_log(request):
    """Returns current content of logger in HTML format"""
    lines = open(os.getcwd() + "/logger.log", "r").read().split('\n')
    log = ""
    ignore = 0
    for line in lines:
        # Ignore celery debug waarning
        if "_showwarnmsg" in line:
            ignore = 5
        if ignore > 0:
            ignore -= 1
        else:
            log += line + "<br>"
    return HttpResponse(log)


@xframe_options_sameorigin
def clean_log(request):
    """Reset logging file"""
    open(os.getcwd() + "/logger.log", "w")
    return HttpResponse()


@xframe_options_sameorigin
def config_complete(request):
    """Config complete, displays configuration and initiatesattacks in \
        various scenarios"""
    if request.method == 'GET':
        config = config_object() 
        link = reverse('device:index')

        reset_db()

        if config.attack_choice == 'ucl' and config.ucl_choice == "bf":
            requests.post(request.build_absolute_uri(
                reverse('attacker:brute-force-user-code')))
        elif config.attack_choice == 'dcl' and config.dcl_choice == "bf":
            requests.post(request.build_absolute_uri(
                reverse('attacker:brute-force-device-code')))
        elif config.attack_choice == 'rp':
            link = reverse('attacker:rp')
        elif config.attack_choice == 'csrfqr':
            link = reverse('attacker:csrfqr')
        elif config.attack_choice == 'dos':
            requests.post(request.build_absolute_uri(reverse('attacker:dos')))

        if (config.attack_choice == 'ucl' and config.ucl_choice == 'sep') \
                or (config.attack_choice == "dcl" and config.dcl_choice == 'sep'):
            sep = "Note that this attack only works when using verification_uri_complete!"
        else: 
            sep = ""
        context = {'config': str(config), 'link': link, 'sep': sep}
        return render(request, 'configuration/configuration-complete.html',
                      context)

    else:
        return HttpResponseForbidden()


@xframe_options_sameorigin
def no_attack(request):
    """Default scenario with no attack"""
    if request.method == 'GET':
        reset_config_db()
        config = config_object()
        config.attack_choice = "no-attack"
        while True:
            try:
                config.save(); break
            except OperationalError:
                pass
        return render(request, 'configuration/no-attack.html')

    else:
        # save config and redirect to config-complete
        config = config_object()
        if 'show_device_name' in request.POST:
            config.show_device_name = True
        if 'show_scope' in request.POST:
            config.show_scope = True
        config.attack_choice = "no-attack"
        while True:
            try:
                config.save(); break
            except OperationalError:
                pass
        logger.warning(config)
        return HttpResponseRedirect(reverse('configuration:config-complete'))


@xframe_options_sameorigin
def ucl(request):
    if request.method == 'GET':
        reset_config_db()
        config = config_object()
        config.attack_choice = "ucl"
        while True:
            try:
                config.save(); break
            except OperationalError:
                pass
        context = {'ucl_choices': UCL_CHOICES}
        return render(request, 'configuration/user-code-leak.html', context)

    else:
        # save config and redirect to config-complete
        config = config_object()
        if 'show_device_name' in request.POST:
            config.show_device_name = True
        if 'show_scope' in request.POST:
            config.show_scope = True
        config.attack_choice = "ucl"
        config.ucl_choice = request.POST['choice']
        config.user_code_entropy = request.POST['entropy']
        if 'rate_limiting' in request.POST:
            config.rate_limiting_ucl = True
        while True:
            try:
                config.save(); break
            except OperationalError:
                pass
        logger.warning(config)
        return HttpResponseRedirect(reverse('configuration:config-complete'))


@xframe_options_sameorigin
def dcl(request):
    if request.method == 'GET':
        reset_config_db()
        config = config_object()
        config.attack_choice = "dcl"
        while True:
            try:
                config.save(); break
            except OperationalError:
                pass
        context = {'dcl_choices': DCL_CHOICES}
        return render(request, 'configuration/device-code-leak.html', context)

    else:
        # save config and redirect to config-complete
        config = config_object()
        if 'show_device_name' in request.POST:
            config.show_device_name = True
        if 'show_scope' in request.POST:
            config.show_scope = True
        config.attack_choice = "dcl"
        config.dcl_choice = request.POST['choice']
        if request.POST['choice'] == "bf":
            config.device_code_entropy = request.POST['entropy']
        if 'rate_limiting' in request.POST:
            config.rate_limiting_dcl = True
        while True:
            try:
                config.save(); break
            except OperationalError:
                pass
        logger.warning(config)
        return HttpResponseRedirect(reverse('configuration:config-complete'))


@xframe_options_sameorigin
def mitm(request):
    if request.method == 'GET':
        reset_config_db()
        config = config_object()
        config.attack_choice = "mitm"
        while True:
            try:
                config.save(); break
            except OperationalError:
                pass
        context = {'mitm_choices': MITM_CHOICES}
        return render(request, 'configuration/man-in-the-middle.html', context)

    else:
        # save config and redirect to config-complete
        config = config_object()
        if 'show_device_name' in request.POST:
            config.show_device_name = True
        if 'show_scope' in request.POST:
            config.show_scope = True
        with_token_respone = request.POST.get('with_token_response', False)
        if with_token_respone:
            config.mitm_choice = 'with_token_response'
        config.attack_choice = "mitm"
        while True:
            try:
                config.save(); break
            except OperationalError:
                pass
        logger.warning(config)
        return HttpResponseRedirect(reverse('configuration:config-complete'))


@xframe_options_sameorigin
def rp(request):
    if request.method == 'GET':
        reset_config_db()
        config = config_object()
        config.attack_choice = "rp"
        while True:
            try:
                config.save(); break
            except OperationalError:
                pass
        context = {'rp_choices': RP_CHOICES}
        return render(request, 'configuration/remote-phishing.html', context)

    else:
        # save config and redirect to config-complete
        config = config_object()
        if 'show_device_name' in request.POST:
            config.show_device_name = True
        if 'show_scope' in request.POST:
            config.show_scope = True
        config.attack_choice = "rp"
        config.rp_choice = request.POST['choice']
        while True:
            try:
                config.save(); break
            except OperationalError:
                pass
        logger.warning(config)
        return HttpResponseRedirect(reverse('configuration:config-complete'))


@xframe_options_sameorigin
def csrfqr(request):
    if request.method == 'GET':
        reset_config_db()
        config = config_object()
        config.attack_choice = "csrfqr"
        while True:
            try:
                config.save(); break
            except OperationalError:
                pass
        return render(request, 'configuration/csrf-with-qr-code.html')

    else:
        # save config and redirect to config-complete
        config = config_object()
        if 'show_device_name' in request.POST:
            config.show_device_name = True
        if 'show_scope' in request.POST:
            config.show_scope = True
        config.attack_choice = "csrfqr"
        while True:
            try:
                config.save(); break
            except OperationalError:
                pass
        logger.warning(config)
        return HttpResponseRedirect(reverse('configuration:config-complete'))


@xframe_options_sameorigin
def cdc(request):
    if request.method == 'GET':
        reset_config_db()
        config = config_object()
        config.attack_choice = "cdc"
        while True:
            try:
                config.save(); break
            except OperationalError:
                pass
        context = {'cdc_choices': CDC_CHOICES}
        return render(request, 'configuration/corrupted-device-client.html',
                      context)

    else:
        # save config and redirect to config-complete
        config = config_object()
        with_authentication = request.POST.get('with_authentication', False)
        if with_authentication:
            config.cdc_choice = 'with_authentication'
        config.attack_choice = "cdc"
        while True:
            try:
                config.save(); break
            except OperationalError:
                pass
        logger.warning(config)
        return HttpResponseRedirect(reverse('configuration:config-complete'))


@xframe_options_sameorigin
def dos(request):
    if request.method == 'GET':
        reset_config_db()
        config = config_object()
        config.attack_choice = "dos"
        while True:
            try:
                config.save(); break
            except OperationalError:
                pass
        return render(request, 'configuration/denial-of-service.html')

    else:
        # save config and redirect to config-complete
        config = config_object()
        if 'show_device_name' in request.POST:
            config.show_device_name = True
        if 'show_scope' in request.POST:
            config.show_scope = True
        config.attack_choice = "dos"
        while True:
            try:
                config.save(); break
            except OperationalError:
                pass
        logger.warning(config)
        return HttpResponseRedirect(reverse('configuration:config-complete'))
