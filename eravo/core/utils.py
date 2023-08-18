import requests

VIRUSTOTAL_API_KEY = 'your_api_key_here'

def fetch_vulnerability_data(software_name, software_version):
    url = f"https://www.virustotal.com/api/v3/search?query={software_name} {software_version}"
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }

    response = requests.get(url, headers=headers)
    data = response.json()

    vulnerabilities = []

    if 'data' in data:
        for item in data['data']:
            vulnerability = {
                'description': item['attributes']['description'],
                'severity': item['attributes']['severity']
            }
            vulnerabilities.append(vulnerability)

    return vulnerabilities
