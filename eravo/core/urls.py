from django.urls import path
from . import views

urlpatterns = [
    path('dashboard/', views.dashboard, name='dashboard'),
    path('populate-scan-results/', views.populate_scan_results, name='populate_scan_results'),
]