from django.db.utils import OperationalError
from django.http.response import HttpResponseForbidden, HttpResponseServerError
from django.shortcuts import render
from django.http import HttpResponse, JsonResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from django.utils.timezone import utc
import json
from urllib.parse import urlencode
from datetime import datetime
from .models import DeviceGrant, User, ClientID, server_monitoring_object
from .tools import AuthenticatedError, access_token_response, add_request_and_get_average, device_registration, rand_bit_length
from configuration.models import config_object
import logging

logger = logging.getLogger(__name__)


def user_code_entry(request):
    """verification_uri is called.

    Returns:
        HttpResponse: user code entry form
    """
    # simulating server overload in DDoS
    if server_monitoring_object().overloaded:
        logger.warning("Server is currently overloaded.")
        return HttpResponseServerError(status=503)

    return render(request, 'authorization_server/login_user_code.html')


def verification_complete(request, user_code):
    """verification_uri_complete with user_code is called.

    Checks validity of user_code and redirects to login.

    Returns:
        HttpResponse: login form if user_code is valid, user code entry form \
            if user_code is invalid
    """
    # Simulating server overload in DDoS
    if server_monitoring_object().overloaded:
        logger.warning("Server is currently overloaded.")
        return HttpResponseServerError(status=503)

    device_grant = None
    try:
        device_grant = DeviceGrant.objects.get(user_code=user_code)
    except DeviceGrant.DoesNotExist:
        # Invalid user code
        context = {'error': 'User Code invalid'}
        return render(request, 'authorization_server/login_user_code.html',
                      context, status=400)

    if not device_grant.user_code_valid():
        # Invalid user code
        context = {'error': 'User Code expired'}
        return render(request, 'authorization_server/login_user_code.html',
                      context, status=400)

    # Continue with login
    logger.warning(
        'Authorization via verification_uri_complete: valid user code \
            received\n user_code: ' + str(user_code))
    config = config_object()
    context = {'user_code': user_code}

    # For User Code Leak not in spatial proximity: show form with advertisement
    if config.ucl_choice == "sep" or config.dcl_choice =="sep":
        context['sep'] = True
    # Display name of device_name and device_code depending on configuration
    if config.show_device_name:
        context['device'] = device_grant.device_name
    if config.attack_choice == "dcl" \
        and (config.dcl_choice == "prox" or config.dcl_choice == "sep"):
        context['device_code'] = device_grant.device_code
    if config.show_scope:
        context['scope'] = device_grant.scope
    return render(request, 'authorization_server/login.html', context)


def process_user_code(request):
    """Checks if entered user_code is in database.

    Args:
        request (HttpRequest): POST with user_code from authentication

    Returns:
        HttpResponse: login page or retry with error
    """
    # Simulating server overload in DDoS
    if server_monitoring_object().overloaded:
        logger.warning("Server is currently overloaded.")
        return HttpResponseServerError(status=503)

    if request.method == 'POST':
        keys = {'user_code'}
        if not keys.issubset(request.POST.keys()):
            return HttpResponseBadRequest()

        user_code = request.POST['user_code']

        device_grant = None
        try:
            device_grant = DeviceGrant.objects.get(user_code=user_code)
        except DeviceGrant.DoesNotExist:
            # Invalid user code
            context = {'error': 'User Code invalid'}
            return render(request, 'authorization_server/login_user_code.html',
                          context, status=400)

        # user_code has expired or already been used (e.g. in User Code Leak)
        if not device_grant.user_code_valid():
            context = {'error': 'User Code expired'}
            return render(request, 'authorization_server/login_user_code.html',
                          context, status=400)

        # Continue with login
        # Display name of device if specified in configuration
        logger.warning('Valid user code entered: ' + str(user_code))
        config = config_object()
        context = {'user_code': user_code}
        if config.show_device_name:
            context['device'] = device_grant.device_name
        if config.attack_choice == "dcl" and config.dcl_choice == "prox":
            context['device_code'] = device_grant.device_code
        if config.show_scope:
            context['scope'] = device_grant.scope

        return render(request, 'authorization_server/login.html', context)

    else:
        return HttpResponseForbidden()


@csrf_exempt
def authenticate_ua(request):
    """User authentication and authorization

    Checks validity of user_code, username and password. Connects the device \
        grant to a user account

    Args:
        request (HttpRequest): Authentication request from user

    Returns:
        HttpResponse: success page or retry with error
    """
    # Simulating server overload in DDoS
    if server_monitoring_object().overloaded:
        logger.warning("Server is currently overloaded.")
        return HttpResponseServerError(status=503)

    if request.method == 'POST':
        keys = {'user_code', 'username', 'password'}
        if not keys.issubset(request.POST.keys()):
            return HttpResponseBadRequest()

        user_code = request.POST['user_code']
        username = request.POST['username']
        password = request.POST['password']
        config = config_object()

        # Rate Limiting for User Code Leak brute force
        if config.attack_choice == "ucl" and config.ucl_choice == "bf" \
                and config.rate_limiting_ucl:
            if add_request_and_get_average(username) > config.max_rate_login:
                context = {'user_code': user_code,
                           'error': 'Too many requests by ' + username 
                                + '. Please try again later.'}
                return render(request,
                              'authorization_server/login_user_code.html',
                              context, status=429)

        # Try to match user_code
        try:
            device_grant = DeviceGrant.objects.get(user_code=user_code)
            if device_grant.authenticated:
                logger.warning("Error: User code " + str(user_code) 
                    + " has already been used to connect to an account.")
                context = {'user_code': user_code,
                       'error': 'User Code invalid'}
                return render(request, 'authorization_server/login_user_code.html',
                            context, status=400)
                
        except DeviceGrant.DoesNotExist:
            # Invalid user_code
            # Redirect to verification_uri
            context = {'user_code': user_code,
                       'error': 'User Code invalid'}
            return render(request, 'authorization_server/login_user_code.html',
                          context, status=400)
        except AuthenticatedError:
            # Redirect to verification_uri
            # grant already completed
            context = {'user_code': user_code,
                       'error': 'Your device is already connected to an account'}
            return render(request, 'authorization_server/login_user_code.html',
                          context, status=400)

        # Authenticate user
        try:
            user = User.objects.get(username=username)
            if (user.password == password):
                while True:
                    try:
                        device_grant.user = user  # connect grant to account
                        device_grant.authenticated = True
                        while True:
                            try:
                                device_grant.save(); break
                            except OperationalError:
                                pass
                        logger.warning(
                            'Device Grant authorization successful. '
                            + device_grant.device_name
                            + ' can now obtain an access_token to access '
                            + str(device_grant.user)
                            + "'s account.\n client_id: "
                            + str(device_grant.client_id)
                            + ', scope: ' + device_grant.scope)
                        return render(request, 'authorization_server/success.html')
                    except:
                        pass
        except:
            pass

        # Login credentials incorrect
        context = {'user_code': user_code,
                   'error': 'Login credentials invalid'}
        if config.show_device_name:
            context['device'] = device_grant.device_name
        if config.attack_choice == "dcl" \
            and (config.dcl_choice == "prox" or config.dcl_choice == "sep"):
            context['device_code'] = device_grant.device_code
        if config.show_scope:
            context['scope'] = device_grant.scope
        return render(request, 'authorization_server/login.html',
                      context, status=400)
    else:
        return HttpResponseForbidden()


@csrf_exempt
def get_client_id(request):
    """Client registration endpoint of AS.
    
    Provice client with client_id unique to AS for initial client device registration.

    Args:
        request (HttpRequest): HTTP request from client

    Returns:
        HttpResponse: client_id
    """
    # simulating server overload in DDoS
    if server_monitoring_object().overloaded:
        logger.warning("Server is currently overloaded.")
        return HttpResponseServerError(status=503)

    if request.method == 'POST':
        device_name = request.POST.get('device_name', '')

        # generate unique client_id with n number of bits
        n = 32
        client_id = rand_bit_length(n)
        try:
            while(ClientID.objects.get(client_id=client_id) is not None):
                client_id = rand_bit_length(n)
        except BaseException:
            pass

        # store client_id in database
        client = ClientID(client_id=client_id, device_name=device_name)
        while True:
            try:
                client.save(); break
            except OperationalError:
                pass


        logger.warning("New client_id issued. \n device_name: "
                       + device_name + ', client_id: ' + str(client_id))
        data = {'client_id': client_id}
        return HttpResponse(content_type='application/x-www-form-urlencoded',
                            content=urlencode(data))
    else:
        return HttpResponseForbidden()


@csrf_exempt
def device_authorization_endpoint(request):
    """Device authorization endpoint of AS.

    Provides client with device_code, user_code, verification_uri, \
        verification_uri_complete, and interval needed for device grant.

    Args:
        request (HttpRequest): HTTP request from client

    Returns:
        HttpResponse: Data needed for authorization or ResponseForbidden
    """
    # simulating server overload in DDoS
    if server_monitoring_object().overloaded:
        logger.warning("Server is currently overloaded.")
        return HttpResponseServerError(status=503)

    if request.method == 'POST':
        client_id = request.POST['client_id']

        try:
            client = ClientID.objects.filter(client_id=client_id).first()
            if client is None:
                raise ClientID.DoesNotExist
            device_name = client.device_name
        except ClientID.DoesNotExist:
            # client_id not registered at AS
            return HttpResponseBadRequest(
                content_type='application/json',
                content=json.dumps({'error': 'invalid_client'}))

        # optional scope
        scope = request.POST.get('scope', None)
        if scope == None:
            scope_log = ""
        else:
            scope_log = ", scope: " + scope

        # create new device grant for device
        device_grant = device_registration(
            client_id, scope, request, device_name)

        logger.warning("New device grant initiated. \n client_id: "
                       + str(client_id) + ", device_name: "
                       + str(device_name) + ", device_code: "
                       + str(device_grant.device_code) + scope_log)
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
    """Token endpoint of the authorization server.

    Called by device client to obtain an access token during polling.
    If the user has approved the grant, a valid access_token and \
        refresh_token is returned.

    Args:
        request (POST request): request must contain valid grant_type, \
            device_code, and client_id

    Returns:
        JsonResponse: depending on status of authorization
    """
    if request.method == 'POST':
        config = config_object()
        # simulating server overload in DDoS
        if config.attack_choice == 'dos':
            averageRequestPerSeconds = add_request_and_get_average(
                "token_endpoint")
            if averageRequestPerSeconds > config.max_rate_dos \
                    or server_monitoring_object().overloaded:
                # server is overloaded
                server_monitor = server_monitoring_object()
                server_monitor.overloaded = True
                while True:
                    try:
                        server_monitor.save(); break
                    except OperationalError:
                        pass
                logger.warning("Server is overloaded. Average number of \
                    requests to token endpoint per second: "
                    + str(averageRequestPerSeconds))
                # Return service unavailable response
                return HttpResponseServerError(status=503)

        # For simulation purposes the functionality of the AS is slightly limited
        # E.g., the polling interval of a client is not checked, slow_down is not implemented.

        # Rate limiting for DCL, an additional POST parameter is used to
        # identify the attacker
        if config.attack_choice == "dcl" and config.dcl_choice == "bf" \
                and config.rate_limiting_dcl:
            if 'polling_id' in request.POST.keys():
                current_rate = add_request_and_get_average(
                    str(request.POST['polling_id']))
                if current_rate > config.max_rate_polling:
                    return JsonResponse(
                        {'error': 'Too many requests: ' + str(current_rate)},
                        status=429)

        # request is missing a required parameter
        keys = {'grant_type', 'device_code', 'client_id'}
        if not keys.issubset(request.POST.keys()):
            logger.warning("invalid_request")
            return HttpResponseBadRequest(
                content_type='application/json',
                content=json.dumps({'error': 'invalid_request'}))

        # retrieve data
        grant_type = request.POST['grant_type']

        # unsupported grant_type
        if grant_type != "urn:ietf:params:oauth:grant-type:device_code":
            logger.warning("unsupported_grant_type")
            return HttpResponseBadRequest(
                content_type='application/json',
                content=json.dumps({'error': 'unsupported_grant_type'}))

        device_code = request.POST['device_code']
        client_id = request.POST['client_id']

        # search for grant
        try:
            device_grant = DeviceGrant.objects.get(client_id=client_id)
        except DeviceGrant.DoesNotExist:
            device_grant = None

        # unknown client
        if (device_grant is None) \
                or (device_grant.device_code != int(device_code)):
            return HttpResponseBadRequest(
                content_type='application/json',
                content=json.dumps({'error': 'invalid_client'}))

        # check if user has approved the grant
        if device_grant.authenticated:
            return access_token_response(device_grant)

        # authorization pending
        dt = datetime.utcnow().replace(tzinfo=utc) \
            - device_grant.creation_timestamp
        # max time in [s] permitted for authentication
        device_grant_duration = 600
        if dt.seconds < device_grant_duration:
            return HttpResponseBadRequest(
                content_type='application/json',
                content=json.dumps({'error': 'authorization_pending'}))

        # device_token has expired, device authorization session has
        # concluded
        else:
            logger.warning("Token has expired.")
            return HttpResponseBadRequest(
                content_type='application/json',
                content=json.dumps({'error': 'expired_token'}))

        # access_denied is not possible in the simulation

    else:
        # Not POST
        return HttpResponseBadRequest(
            content_type='application/json',
            content=json.dumps({'error': 'invalid_request'}))

@csrf_exempt
def find_client_id(request):
    """Returns publically available client_id for given device_code"""
    if request.method == 'POST':
        keys = {'device_code'}
        if not keys.issubset(request.POST.keys()):
            return HttpResponseBadRequest()
        else:
            device_code = request.POST['device_code']
            # search for grant
            try:
                device_grant = DeviceGrant.objects.get(device_code=device_code)
                return JsonResponse({'client_id': device_grant.client_id})
            except DeviceGrant.DoesNotExist:
                return HttpResponseBadRequest()
    else:
        return HttpResponseBadRequest()