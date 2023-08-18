from django.db import models


class SecurityReport(models.Model):
    target_type = models.CharField(max_length=20, choices=[('file', 'File'), ('url', 'URL'), ('domain', 'Domain'), ('ip', 'IP Address')])
    target_value = models.CharField(max_length=255)
    report_generated_at = models.DateTimeField(auto_now_add=True)
    # Add more fields as needed


class ScanResult(models.Model):
    scan_id = models.CharField(max_length=100, unique=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    sha256 = models.CharField(max_length=64)
    detected = models.BooleanField()
    threat_name = models.CharField(max_length=100)
    scan_engine = models.CharField(max_length=100)
    security_report = models.ForeignKey(SecurityReport, on_delete=models.CASCADE)
    data_source = models.CharField(max_length=100)
    report_data = models.JSONField()


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
