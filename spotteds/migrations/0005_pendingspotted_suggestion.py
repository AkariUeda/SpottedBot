# -*- coding: utf-8 -*-
# Generated by Django 1.10.5 on 2017-02-06 15:49
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("spotteds", "0004_pendingspotted_attachment_safe"),
    ]

    operations = [
        migrations.AddField(
            model_name="pendingspotted",
            name="suggestion",
            field=models.CharField(default="", max_length=100),
        ),
    ]
