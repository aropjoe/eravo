import subprocess
import re
import requests

# Get a list of installed programs using PowerShell
def get_installed_apps():
    cmd = "Get-WmiObject -Class Win32_Product | Select-Object Name, Version"
    result = subprocess.run(["powershell", cmd], capture_output=True, text=True)

    installed_apps = []
    if result.returncode == 0:
        output = result.stdout
        for match in re.finditer(
            r"Name\s*:\s*(.*?)\s*Version\s*:\s*(.*?)\s*", output, re.IGNORECASE
        ):
            name = match.group(1)
            version = match.group(2)
            installed_apps.append({"name": name, "version": version})
    return installed_apps


def send_apps_to_django(apps):
    api_url = "http://your-django-app-url/api/analyze-apps/"

    headers = {"Content-Type": "application/json"}

    data = {"apps": apps}

    response = requests.post(api_url, json=data, headers=headers)

    if response.status_code == 200:
        print("Apps sent to Django platform successfully.")
    else:
        print("Failed to send apps to Django platform.")


if __name__ == "__main__":
    installed_apps = get_installed_apps()
    send_apps_to_django(installed_apps)
