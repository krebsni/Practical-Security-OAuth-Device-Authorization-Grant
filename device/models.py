from django.db import models
from datetime import datetime
from django.utils.timezone import utc


def reset_device_db():
    DeviceGrant.objects.all().delete()


class DeviceGrant(models.Model):
    device_code = models.BigIntegerField()
    authenticated = models.BooleanField(default=False)
    client_id = models.IntegerField()
    user_code = models.IntegerField()
    user_code_lifetime = models.IntegerField()
    verification_uri = models.CharField(max_length=50)
    verification_uri_complete = models.CharField(max_length=100)
    interval = models.IntegerField(default=5)  # interval in [s]
    scope = models.CharField(max_length=20, blank=True,
                             null=True) 
    creation_timestamp = models.DateTimeField(auto_now=True)
    access_token = models.IntegerField(blank=True, null=True)
    access_token_creation_timestamp = models.DateTimeField(
        blank=True, null=True)
    # Determines how long access_token is valid for from creation date in seconds
    access_token_lifetime = models.IntegerField(default=604800)
    refresh_token = models.IntegerField(blank=True, null=True)
    request_denied = models.BooleanField(default=False)
    device_name = models.CharField(max_length=40, default="")
    timeout = models.BooleanField(default=False)
    service_unavailable = models.BooleanField(default=False)

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
