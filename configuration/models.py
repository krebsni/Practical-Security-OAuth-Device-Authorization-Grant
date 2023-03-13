from django.db import models

ATTACK_CHOICES = {
    'no-attack': 'No Attack',
    'ucl': 'User Code Leak',
    'dcl': 'Device Code Leak',
    'mitm': 'Man in the Middle',
    'rp': 'Remote Phishing',
    'csrfqr': 'CSRF with QR-Code',
    'cdc': 'Corrupted Device Client',
    'dos': 'Denial of Service'
}

UCL_CHOICES = {
    'prox': 'Attacker in spatial proximity',
    'sep': 'Attacker not in spatial proximity (using Referer Header)',
    'bf': 'Brute Force',
    '': ''
}

DCL_CHOICES = {
    'prox': 'Attacker in spatial proximity',
    'sep': 'Attacker not in spatial proximity (using Referer Header)',
    'bf': 'Brute Force',
    '': ''
}

MITM_CHOICES = {
    'with_token_response': 'Attacker forwards the device access token \
        response from the AS to the device',
    '': ''
}

CDC_CHOICES = {
    'with_authentication': "Attacker completes Device Flow",
    '': ''
}
RP_CHOICES = {
    'direct': 'Link in Email is verification_uri_complete',
    'indirect': "Link in Email redirects to Eve's server to obtain a new \
        user_code"
}


def reset_config_db():
    AttackConfiguration.objects.all().delete()


def config_object():
    """Returns config object or creates new if none exists"""
    while True:
        try:
            if AttackConfiguration.objects.exists():
                return AttackConfiguration.objects.first()
            else:
                c = AttackConfiguration()
                c.save()
                return c
        except:
            pass


class AttackConfiguration(models.Model):
    id = models.IntegerField(default=1, primary_key=True)
    attack_choice = models.CharField(
        default='no-attack', max_length=10, choices=ATTACK_CHOICES.items())
    ucl_choice = models.CharField(
        default='', max_length=4, choices=UCL_CHOICES.items())
    dcl_choice = models.CharField(
        default='', max_length=4, choices=DCL_CHOICES.items())
    mitm_choice = models.CharField(
        default='', max_length=20, choices=MITM_CHOICES.items())
    cdc_choice = models.CharField(
        default='', max_length=25, choices=CDC_CHOICES.items())
    rp_choice = models.CharField(
        default='', max_length=25, choices=RP_CHOICES.items())
    # Show device name during login at AS
    show_device_name = models.BooleanField(default=False)
    # Show scooe during login at AS
    show_scope = models.BooleanField(default=False)
    # [s] interval specified by AS for polling (value 1 for quicker result)
    interval = models.IntegerField(default=1)
    # Timeout, e.g. for polling
    timeout = models.IntegerField(default=30)
    # Relevant for User Code Leak brute force
    user_code_entropy = models.IntegerField(default=20)
    # Rate limiting for authentication for User Code Leak brute force
    max_rate_login = models.IntegerField(default=3)
    rate_limiting_ucl = models.BooleanField(default=False)
    # Relevant for Device Code Leak brute force attack
    device_code_entropy = models.IntegerField(default=20)
    # Rate limiting for polling (for Device Code Leak brute force)
    max_rate_polling = models.IntegerField(default=3)
    rate_limiting_dcl = models.BooleanField(default=False)
    # Number of concurrent client devices the attacker uses during DDoS
    number_of_devices = models.IntegerField(default=20)
    # Rate limiting of token endpoint requests during DDoS
    max_rate_dos = models.FloatField(default=2.5)
    

    def sub_choice(self):
        """Shows additional attack scenario specific information"""
        if self.attack_choice == 'ucl':
            if self.ucl_choice == 'bf':
                return ', ' + UCL_CHOICES.get(self.ucl_choice) \
                    + ", user_code_entropy: " + str(self.user_code_entropy)
            else:
                return ', ' + UCL_CHOICES.get(self.ucl_choice)
        elif self.attack_choice == 'dcl':
            if self.dcl_choice == 'bf':
                return ', ' + UCL_CHOICES.get(self.dcl_choice) \
                    + ", device_code_entropy: " + str(self.device_code_entropy)
            else:
                return ', ' + UCL_CHOICES.get(self.dcl_choice)
        elif self.attack_choice == 'mitm':
            if self.mitm_choice != '':
                return ', ' + MITM_CHOICES.get(self.mitm_choice)
            else:
                return ', Attacker does not forward the device access token \
                    response from Alice-AS to the device'
        elif self.attack_choice == 'rp':
            return ', ' + RP_CHOICES.get(self.rp_choice)
        elif self.attack_choice == 'cdc':
            if self.cdc_choice != '':
                return ', ' + CDC_CHOICES.get(self.cdc_choice)
            else:
                return ', Attacker does not complete Device Flow; no polling or \
                    user authentication at AS'
        elif self.attack_choice == 'dos':
            return ', number_of_devices: ' + str(self.number_of_devices) + \
                ', max requests/s at AS: ' + str(self.max_rate_dos)
        else:
            return ''

    def show_name(self):
        """Show device name option"""
        if not self.attack_choice == 'cdc':
            if self.show_device_name:
                return ', Alice-AS shows device name during authorization'
            else:
                return ', Alice-AS does not show device name during \
                    authorization'
        else:
            return ''
    def show_scope_in_login(self):
        """Show scope option"""
        if not self.attack_choice == 'cdc':
            if self.show_scope:
                return ', Alice-AS shows scope during authorization'
            else:
                return ', Alice-AS does not show scope during \
                    authorization'
        else:
            return ''

    def rate_limiting(self):
        """Show additional attack scenario specific information"""
        if self.attack_choice == 'ucl' and self.ucl_choice == 'bf':
            if self.rate_limiting_ucl:
                return ', with rate limiting'
            else:
                return ', without rate limiting'
        elif self.attack_choice == 'dcl' and self.dcl_choice == 'bf':
            if self.rate_limiting_dcl:
                return ', with rate limiting'
            else:
                return ', without rate limiting'
        else:
            return ''

    def __str__(self):
        """Displays most important information of attack configuration"""
        return "Configuration: " + ATTACK_CHOICES.get(self.attack_choice) \
            + self.sub_choice() + self.show_name() + self.show_scope_in_login() + self.rate_limiting()
