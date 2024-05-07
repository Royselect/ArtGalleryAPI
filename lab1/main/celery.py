from celery import Celery
from celery.schedules import crontab

app = Celery('lab1')

app.conf.beat_schedule = {
    'send-report-task': {
        'task': 'lab1.tasks.send_report',
        'schedule': crontab(hour=0, minute=0),  # Выполнять задачу каждый день в полночь
    },
}