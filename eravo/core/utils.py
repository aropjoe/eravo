import requests
from .models import SecurityReport, ScanResult, MaliciousItem
from .integrations import fetch_virustotal_data


VIRUSTOTAL_API_KEY = "your_api_key_here"


def fetch_vulnerability_data(software_name, software_version):
    url = f"https://www.virustotal.com/api/v3/search?query={software_name} {software_version}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    response = requests.get(url, headers=headers)
    data = response.json()

    vulnerabilities = []

    if "data" in data:
        for item in data["data"]:
            vulnerability = {
                "description": item["attributes"]["description"],
                "severity": item["attributes"]["severity"],
            }
            vulnerabilities.append(vulnerability)

    return vulnerabilities


def generate_security_report(target_type, target_value):
    # Fetch data from VirusTotal and other sources
    report_data = fetch_virustotal_data(target_type, target_value)
    # Create SecurityReport entry
    security_report = SecurityReport.objects.create(
        target_type=target_type, target_value=target_value
    )
    # Create ScanResult entries
    for data_source, data in report_data.items():
        ScanResult.objects.create(
            security_report=security_report, data_source=data_source, report_data=data
        )
    return security_report


def analyze_malicious_item(malicious_item):
    # Fetch data from security data sources
    detection_result = fetch_detection_result(
        malicious_item.item_type, malicious_item.value
    )
    malicious_item.detection_result = detection_result
    malicious_item.save()


def fetch_detection_result(item_type, value):
    # Implement logic to fetch detection result using security data sources
    # Return a dictionary containing detection insights
    return {"insights": "detection_insights"}



def search_iocs_in_virustotal(query):
    url = f"https://www.virustotal.com/api/v3/intelligence/search?query={query}"
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY,
    }

    response = requests.get(url, headers=headers)
    data = response.json()

    if 'data' in data:
        return data['data']
    else:
        return []
