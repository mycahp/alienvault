# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models

class Traffic(models.Model):
    address = models.TextField()
    timestamp = models.TextField()
    endpoint = models.TextField()
    alienvault_id = models.TextField()
