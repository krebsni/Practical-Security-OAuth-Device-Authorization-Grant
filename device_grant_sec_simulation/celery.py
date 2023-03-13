import os
from celery import Celery

from django.apps import apps
import celery.signals

# set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE',
                      'device_grant_sec_simulation.settings')
app = Celery('device_grant_sec_simulation')

app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django app configs.
app.autodiscover_tasks()


@app.task(bind=True)
def debug_task(self):
    print('Request: {0!r}'.format(self.request))


@celery.signals.setup_logging.connect
def on_celery_setup_logging(**kwargs):
    pass
