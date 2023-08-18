import requests
from .models import ScanResult
from django.http import HttpResponse
import json
import time
from .forms import ScanForm


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
