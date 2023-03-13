from django.db.utils import OperationalError
from django.db import models
from datetime import datetime
from django.utils.timezone import utc
from configuration.models import config_object


def reset_AS_db():
    """Resets attacker database and add Bob and Eve as users"""
    DeviceGrant.objects.all().delete()
    ClientID.objects.all().delete()
    User.objects.all().delete()
    RequestCounter.objects.all().delete()
    ServerMonitoring.objects.all().delete()
    u1 = User(username='Bob', password='good')
    u2 = User(username='Eve', password='evil')
    while True:
        try:
            u1.save(); break
        except OperationalError:
            pass
    while True:
        try:
            u2.save(); break
        except OperationalError:
            pass


def server_monitoring_object():
    """Returns server monitoring object"""
    if ServerMonitoring.objects.exists():
        return ServerMonitoring.objects.first()
    else:
        server = ServerMonitoring()

        while True:
            try:
                server.save(); break
            except OperationalError:
                pass
        return server


def server_overloaded_ddos():
    """Returns True if server overloaded in DDos at token endpoint"""
    try:
        while True:
            try:
                counter = RequestCounter.objects.get(
                    counter_name="token_endpoint"); break
            except RequestCounter.DoesNotExist:
                break
        if counter > config_object().max_rate_dos:
            return True
        else:
            return False
    except:
        return False


class User(models.Model):
    """Insecurely stores user and password for simulation purposes"""
    username = models.CharField(max_length=20)
    password = models.CharField(max_length=20)

    def __str__(self):
        return self.username


class DeviceGrant(models.Model):
    """Contains all relevant information for a device grant instance"""
    device_code = models.BigIntegerField()
    device_name = models.CharField(max_length=30, default="")
    client_id = models.IntegerField()
    user_code = models.IntegerField()
    # lifetime of user_code in seconds
    user_code_lifetime = models.IntegerField(default=1800)
    verification_uri = models.CharField(max_length=50)
    verification_uri_complete = models.CharField(max_length=100)
    interval = models.IntegerField(default=5)  # interval in [s]
    scope = models.CharField(max_length=20, blank=True,
                             null=True)
    creation_timestamp = models.DateTimeField(auto_now=True)
    # indicate status of device grant, True if user authorized device
    authenticated = models.BooleanField(default=False)
    access_token = models.IntegerField(blank=True, null=True)
    access_token_creation_timestamp = models.DateTimeField(
        blank=True, null=True)
    # Determines how long access_token is valid for from creation date in seconds
    access_token_lifetime = models.IntegerField(default=604800)
    refresh_token = models.IntegerField(blank=True, null=True)
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, blank=True, null=True)

    def user_code_expires_in(self):
        """
        Calculate seconds to expiration of user_code and device_code

        returns -1 if invalid
        """
        dt = datetime.utcnow().replace(tzinfo=utc) - self.creation_timestamp
        if dt.total_seconds() < self.user_code_lifetime:
            return self.user_code_lifetime - dt.total_seconds()
        else:
            return -1

    def user_code_valid(self):
        """checks is user_code and device_code are still valid for device grant

        Returns:
            bool: True if valid
        """
        if (self.user_code_expires_in() != -1) and not self.authenticated:
            return True
        else:
            return False

    def access_token_expires_in(self):
        """
        Calculate seconds to expiration of access_token

        returns -1 if invalid
        """
        if self.access_token != None:
            dt = datetime.utcnow().replace(tzinfo=utc) - self.access_token_creation_timestamp
            if dt.total_seconds() < self.access_token_lifetime:
                return self.access_token_lifetime - dt.total_seconds()
        else:
            return -1

    def __str__(self):
        return "Grant user_code=" + str(self.user_code) + " authenticated=" + str(self.authenticated)


class ClientID(models.Model):
    """Used to ensure uniqueness of client_id before device grant is initiated"""
    client_id = models.BigIntegerField()
    device_name = models.CharField(max_length=30, default="")


class RequestCounter(models.Model):
    """Counter used to calculate average of requests for DDoS and rate limiting"""
    counter_name = models.CharField(max_length=30, primary_key=True)
    counter = models.IntegerField(default=0)
    last_request_time = models.DateTimeField()
    average = models.FloatField(default=1.0)


class ServerMonitoring(models.Model):
    """Used for simulating server overload during DDoS"""
    overloaded = models.BooleanField(default=False)