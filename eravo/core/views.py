import requests
from .models import ScanResult, Software, Vulnerability, SecurityReport, Incident, MaliciousItem
from django.http import HttpResponse
import json
import time
from .forms import ScanForm, SecurityReportForm, IncidentForm, MaliciousItemForm
from django.shortcuts import render, get_object_or_404
from .utils import fetch_vulnerability_data, generate_security_report, analyze_malicious_item
from django.http import JsonResponse
from rest_framework.decorators import api_view


VIRUSTOTAL_API_KEY = 'your_api_key_here'

MAX_REQUESTS_PER_MINUTE = 10
MINUTE = 60

last_request_time = 0



def fetch_virustotal_data(sha256):
    global last_request_time

    current_time = time.time()
    elapsed_time = current_time - last_request_time

    if elapsed_time < (MINUTE / MAX_REQUESTS_PER_MINUTE):
        time_to_wait = (MINUTE / MAX_REQUESTS_PER_MINUTE) - elapsed_time
        time.sleep(time_to_wait)

    last_request_time = current_time

    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


def populate_scan_results(request):
    if request.method == 'POST':
        form = ScanForm(request.POST)
        if form.is_valid():
            sha256 = form.cleaned_data['sha256']
            response_data = fetch_virustotal_data(sha256)
            
            if 'data' in response_data:
                data = response_data['data']
                scan_id = data['id']
                detected = data['attributes']['last_analysis_stats']['malicious']
                threat_name = data['attributes']['last_analysis_results'][0]['result']
                scan_engine = data['attributes']['last_analysis_results'][0]['engine_name']

                ScanResult.objects.create(
                    scan_id=scan_id,
                    sha256=sha256,
                    detected=detected,
                    threat_name=threat_name,
                    scan_engine=scan_engine
                )

                return HttpResponse("Scan result saved successfully.")
            else:
                return HttpResponse("No data found for the provided SHA256.")
        else:
            return HttpResponse("Invalid input.")
    else:
        form = ScanForm()

    return render(request, 'populate_scan_results.html', {'form': form})


def software_input(request):
    if request.method == 'POST':
        software_name = request.POST.get('software_name')
        software_version = request.POST.get('software_version')
        software = Software.objects.get_or_create(name=software_name, version=software_version)
        vulnerability_data = fetch_vulnerability_data(software_name, software_version)
        vulnerabilities = []

        for vuln in vulnerability_data:
            vulnerability = Vulnerability.objects.create(
                software=software,
                description=vuln['description'],
                severity=vuln['severity']
            )
            vulnerabilities.append(vulnerability)

        return render(request, 'results.html', {'software': software, 'vulnerabilities': vulnerabilities})

    return render(request, 'input.html')


@api_view(['POST'])
def analyze_installed_apps(request):
    if request.method == 'POST':
        apps = request.data.get('apps', [])
        # Process the received apps and perform vulnerability analysis
        # Return analysis results as JSON response
        return JsonResponse({"results": "vulnerability_analysis_results"})


def check_phishing(url):
    url = f"https://www.virustotal.com/api/v3/urls/{url}"
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }

    response = requests.get(url, headers=headers)
    data = response.json()

    if 'data' in data:
        attributes = data['data']['attributes']
        if 'last_analysis_stats' in attributes:
            if attributes['last_analysis_stats']['malicious'] > 0:
                return "Potentially phishing"
        return "Safe"
    else:
        return "Unknown"

#if __name__ == "__main__":
#    url = input("Enter the URL to check: ")
#    result = check_phishing(url)
#    print(f"URL: {url} - Status: {result}")


def generate_report(request):
    if request.method == 'POST':
        form = SecurityReportForm(request.POST)
        if form.is_valid():
            target_type = form.cleaned_data['target_type']
            target_value = form.cleaned_data['target_value']
            security_report = generate_security_report(target_type, target_value)
            return render(request, 'report.html', {'security_report': security_report})
    else:
        form = SecurityReportForm()

    return render(request, 'generate_report.html', {'form': form})


def create_incident(request):
    if request.method == 'POST':
        incident_form = IncidentForm(request.POST)
        malicious_item_form = MaliciousItemForm(request.POST)
        if incident_form.is_valid() and malicious_item_form.is_valid():
            incident = incident_form.save()
            malicious_item = malicious_item_form.save(commit=False)
            malicious_item.incident = incident
            malicious_item.save()
            analyze_malicious_item(malicious_item)
            return render(request, 'incident_details.html', {'incident': incident})
    else:
        incident_form = IncidentForm()
        malicious_item_form = MaliciousItemForm()

    return render(request, 'create_incident.html', {'incident_form': incident_form, 'malicious_item_form': malicious_item_form})


def view_incident(request, incident_id):
    incident = get_object_or_404(Incident, id=incident_id)
    return render(request, 'incident_details.html', {'incident': incident})
