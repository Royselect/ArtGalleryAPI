from datetime import datetime, timedelta, UTC
from django.conf import settings
from django_cron import CronJobBase, Schedule
# from models import LogiFromMethods
from .tasks import generate_report



class CreateLog(CronJobBase):
    RUN_EVERY_MINS = settings.CRON_COLLECT_STATISTICS_IN_MINS
    schedule = Schedule(run_every_mins=RUN_EVERY_MINS)
    code = 'main.CreateLog'

    def do(self):
        generate_report()
    
