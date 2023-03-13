from django.db.utils import OperationalError
from django.db import models
from django.utils.timezone import utc
from datetime import datetime
import logging


logger = logging.getLogger(__name__)


def reset_attacker_db():
    """Resets attacker database and initiate utility object"""
    while True:
        try:
            DeviceGrant.objects.all().delete()
            User.objects.all().delete()
            ClientID.objects.all().delete()
            Utility.objects.all().delete()
            u = Utility()
            u.save(); break
        except OperationalError:
            pass


def utility_object():
    """Returns utility object"""
    while True:
        try:
            if Utility.objects.exists():
                return Utility.objects.first()
        except:
            pass


class User(models.Model):
    """Insecurely stores user and password for simulation purposes"""
    username = models.CharField(max_length=20)
    password = models.CharField(max_length=20)

    def __str__(self):
        return self.username


class DeviceGrant(models.Model):
    """Contains all relevant information for a device grant instance"""
    device_code = models.BigIntegerField()
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
    device_name = models.CharField(max_length=30, default="")

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
        if self.user_code_expires_in() != -1:
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


class ClientID(models.Model):
    """Used to ensure uniqueness of client_id before device grant is initiated"""
    client_id = models.IntegerField()
    device_name = models.CharField(max_length=30, default="")
    

class Utility(models.Model):
    """Used to access start time and determine whether the attack has terminated accross tasks"""
    # attack successful => other polling tasks can terminate, too
    terminated = models.BooleanField(default=False)
    # start time of polling => to synchronize timeout for tasks in brute force
    start_time = models.DateTimeField(blank=True, null=True)
