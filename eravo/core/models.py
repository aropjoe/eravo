from django.db import models

class ScanResult(models.Model):
    scan_id = models.CharField(max_length=100, unique=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    sha256 = models.CharField(max_length=64)
    detected = models.BooleanField()
    threat_name = models.CharField(max_length=100)
    scan_engine = models.CharField(max_length=100)

class GeographicOrigin(models.Model):
    country = models.CharField(max_length=100)
    count = models.PositiveIntegerField()

class IndustryTarget(models.Model):
    industry = models.CharField(max_length=100)
    count = models.PositiveIntegerField()
