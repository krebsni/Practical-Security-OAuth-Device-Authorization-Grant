from django.utils.timezone import utc
from django.db.utils import OperationalError
from celery import shared_task
from configuration.models import config_object
from .models import DeviceGrant
from urllib.parse import urlencode
import requests
import time
from datetime import datetime
import logging

logger = logging.getLogger(__name__)
HEADERS = {'Content-type': 'application/x-www-form-urlencoded'}


@shared_task
def polling(client_id, token_endpoint_url):
    """Polling for access_token.

    Sends periodic POST requests to token endpoint of AS. Period length is specified by interval. Terminates

    Args:
        device_grant (DeviceGrant): database entry from DeviceGrant
    """
    # retrieve device_grant object for client_id
    try:
        device_grant = DeviceGrant.objects.get(client_id=client_id)
    except DeviceGrant.DoesNotExist:
        logger.error("Error during polling, no device grant with client_id " 
            + client_id)
        return

    log_device_name = ""
    if device_grant.device_name != "":
        log_device_name = "\n device_name: " + device_grant.device_name
    logger.warning("Start polling." + log_device_name)

    # poll until timeout, success or denied if user code is valid
    start = time.time()
    success = False
    while (time.time() - start < config_object().timeout) and not success \
            and not device_grant.request_denied and device_grant.user_code_valid():
        # wait according to interval length
        if config_object().attack_choice != "dos":
            time.sleep(device_grant.interval)

        data = {'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
                'device_code': device_grant.device_code,
                'client_id': device_grant.client_id}

        # send access_token request to token endpoint
        request = requests.post(
            token_endpoint_url, headers=HEADERS, data=urlencode(data))

        if request.status_code == 200:
            # polling successful
            data = request.json()
            while True:
                try:
                    device_grant.authenticated = True
                    device_grant.access_token = data['access_token']
                    device_grant.access_token_creation_timestamp = datetime.utcnow().replace(tzinfo=utc)
                    device_grant.access_token_lifetime = data['expires_in']
                    device_grant.refresh_token = data['refresh_token']
                    device_grant.save()
                    break
                except OperationalError:
                    pass
            success = True
            logger.warning("Grant successful. Device is registered." + log_device_name)

        elif request.status_code == 400:
            # polling not successful, handle error messages
            error = request.json()['error']
            if error == 'authorization_pending':
                # user has not completed authorization
                logger.info("Wait for authorization to complete")
            elif error == 'slow_down':
                # increase interval by 5 seconds, actually not used in the simulation
                logger.info("Wait for authorization to complete. Slowing down polling." 
                            + log_device_name)
                device_grant.interval += 5
                while True:
                    try:
                        device_grant.save(); break
                    except OperationalError:
                        pass
            else:
                # error of type invalid_request, access_denied, unsupported_grant_type, 
                # invalid_client, or expired_token
                logger.warning("An error occured during polling: " + error 
                                + ". Please try again." + log_device_name)
                device_grant.request_denied = True
                while True:
                    try:
                        device_grant.save(); break
                    except OperationalError:
                        pass

        elif request.status_code == 503:
            logger.warning("An error occured during polling. \
                Service Unavailable.")
            device_grant.service_unavailable = True
            while True:
                try:
                    device_grant.save(); break
                except OperationalError:
                    pass
        else:
            device_grant.request_denied = True
            while True:
                try:
                    device_grant.save(); break
                except OperationalError:
                    pass
            logger.warning("An unkown error occured during polling. \
                Status code: " + str(request.status_code) 
                + log_device_name)

    if not success:
        device_grant.timeout = True
        while True:
            try:
                device_grant.save(); break
            except OperationalError:
                pass

        logger.warning("Timeout during polling. Device grant unsuccessful." 
            + log_device_name)
