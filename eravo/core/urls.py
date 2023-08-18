from django.urls import path
from . import views

urlpatterns = [
    path("dashboard/", views.dashboard, name="dashboard"),
    path(
        "populate-scan-results/",
        views.populate_scan_results,
        name="populate_scan_results",
    ),
    path(
        "api/analyze-apps/", views.analyze_installed_apps, name="analyze_installed_apps"
    ),
    path("generate/", views.generate_report, name="generate_report"),
    path("report/<int:security_report_id>/", views.view_report, name="view_report"),
    path("create/", views.create_incident, name="create_incident"),
    path("incident/<int:incident_id>/", views.view_incident, name="view_incident"),
]
