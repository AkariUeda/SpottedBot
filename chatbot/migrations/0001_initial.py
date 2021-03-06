# Generated by Django 2.0.3 on 2018-05-30 02:48

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="Chat",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("uid", models.CharField(max_length=200, unique=True)),
                ("standby", models.BooleanField(default=False)),
                ("standby_dt", models.DateTimeField(default=django.utils.timezone.now)),
            ],
        ),
    ]
