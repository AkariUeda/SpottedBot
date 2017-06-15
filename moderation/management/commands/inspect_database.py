from django.core.management.base import BaseCommand
from datetime import timedelta
from django.utils import timezone

from custom_auth.models import FacebookUser
from django.contrib.auth.models import User
from moderation.models import Moderator, WorkHour
from spotteds.models import Spotted, PendingSpotted

now = timezone.now()


class Command(BaseCommand):
    help = 'Inspect Database'

    def handle(self, *args, **options):

        tables = {
            "FacebookUser": len(FacebookUser.objects.all()),
            "User": len(User.objects.all()),
            "Moderator": len(Moderator.objects.all()),
            "WorkHour": len(WorkHour.objects.all()),
            "Spotted": len(Spotted.objects.all()),
            "PendingSpotted": len(PendingSpotted.objects.all())
        }

        text = ""
        count = 0
        for key, value in tables.items():
            text += "\n{} has {} rows".format(key, value)
            count += value

        text += "\n\nTotal editable rows: {}".format(count)

        return text
