from django.db.utils import IntegrityError, OperationalError
from django.http.response import JsonResponse
from django.utils.cache import patch_cache_control
from configuration.models import config_object
from random import randint
from .models import DeviceGrant, RequestCounter
from datetime import datetime
from django.utils.timezone import utc
import logging

logger = logging.getLogger(__name__)


class AuthenticatedError(Exception):
    """Raised if device grant has already been authorized by user during authentication"""
    pass


def device_registration(client_id, scope, request, device_name):
    """Generates parameters for new authorization request.

    New parameters include device_code, user_code, and verification_uri, \
        verification_uri_complete.
    Save request as db entry in DeviceGrant. Creation time is set to now, \
        interval and scope are stored.

    Args:
        client_id (int): ID of client device unique to AS
        scope (str): requested scope
        request (HttpRequest): HTTP request from client

    Returns:
        DeviceGrant: new authorization request
    """
    config = config_object()
    # generate unique device_code with n1 number of bits
    n1 = config.device_code_entropy
    device_code = rand_bit_length(n1)
    try:
        while(DeviceGrant.objects.get(device_code=device_code) is not None):
            device_code = rand_bit_length(n1)
    except:
        pass

    # generate user_code with n2 number of bits
    n2 = config.user_code_entropy
    user_code = rand_bit_length(n2)

    # build verification_uri_complete
    verification_uri = request.build_absolute_uri(
        '/authorization-server/device')
    verification_uri_complete = verification_uri + "/" + str(user_code)

    # save new grant in database
    device_grant = DeviceGrant(
        device_code=device_code,
        device_name=device_name,
        client_id=client_id,
        user_code=user_code,
        verification_uri=verification_uri,
        verification_uri_complete=verification_uri_complete,
        interval=config.interval, scope=scope)
    while True:
        try:
            device_grant.save(); break
        except OperationalError: 
            pass

    return device_grant


def access_token_response(device_grant):
    """Generates HTTP response with access_token for device_grant

    access_token, token_type, expires_in, refresh_token are generated \
        randomly with specified n.
    Response is JsonResponse including the above and scope.

    Args:
        device_grant (DeviceGrant): device that is authorized to get \
            access to user account

    Returns:
        HttpResponse: contains generated access_token and optional \
            refresh_token
    """
    # Generate access_token and refresh_token and set creation date
    if device_grant.access_token is None:
        n = 32
        device_grant.access_token = rand_bit_length(n)
        device_grant.refresh_token = rand_bit_length(n)  # not used
        device_grant.access_token_creation_timestamp = \
            datetime.utcnow().replace(tzinfo=utc)
        while True:
            try:
                device_grant.save(); break
            except OperationalError: 
                pass

        logger.warning("Successful access_token request. New \
                            access_token issued.\n client_id: "
                       + str(device_grant.client_id) + ", access_token: "
                       + str(device_grant.access_token))
    else:
        logger.warning(
            "Successful access_token request.\n \
                client_id: " + str(device_grant.client_id)
            + ", access_token: " + str(device_grant.access_token))
    data = {
        'access_token': device_grant.access_token,
        'token_type': 'empty', 
        'expires_in': device_grant.access_token_expires_in(),
        'refresh_token': device_grant.refresh_token,
        'scope': device_grant.scope, 
    }
    response = JsonResponse(data=data)
    patch_cache_control(response, no_cache=True)
    return response


def rand_bit_length(n):
    """Computes random number of n bits

    Args:
        n (int): number of bits
    """
    return randint(2**(n - 1), (2**n) - 1)


def add_request_and_get_average(counter_name):
    """Increments counter and returns average requests/s

    During the first 2 seconds of counting, the average will be 1.
    The average is estimated over approximately 2-sec intervals.

    Returns:
        float: average requests per second
    """
    # sqlite3 is quite buggy for highly concurrent transactions
    counter = None
    while True:
        try:
            counter = RequestCounter.objects.get(
                counter_name=counter_name); break
        except RequestCounter.DoesNotExist:
            counter = RequestCounter(
                counter_name=counter_name, 
                last_request_time=datetime.utcnow().replace(tzinfo=utc))
            break
    
    counter.counter += 1
    while True:
        try:
            counter.save(); break
        except OperationalError:
            pass
        except IntegrityError: 
            while True:
                try:
                    counter = RequestCounter.objects.get(
                        counter_name=counter_name); break
                except RequestCounter.DoesNotExist:
                    counter = RequestCounter(
                        counter_name=counter_name, 
                        last_request_time=datetime.utcnow().replace(tzinfo=utc))
                    break
            counter.counter += 1
            while True:
                try:
                    counter.save(); break
                except OperationalError:
                    pass

    diff: datetime = datetime.utcnow().replace(tzinfo=utc) \
        - counter.last_request_time
    if(diff.total_seconds() >= 2):
        counter.average = counter.counter / diff.total_seconds()
        counter.counter = 0
        counter.last_request_time = datetime.utcnow().replace(tzinfo=utc)
        success = False
        while True:
            try:
                counter.save(); break
            except OperationalError:
                pass

    return counter.average