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


class Software(models.Model):
    name = models.CharField(max_length=100)
    version = models.CharField(max_length=20)
    # Add more fields as needed


class Vulnerability(models.Model):
    software = models.ForeignKey(Software, on_delete=models.CASCADE)
    description = models.TextField()
    severity = models.CharField(max_length=10)
    # Add more fields as needed
