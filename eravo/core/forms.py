from django import forms


class ScanForm(forms.Form):
    sha256 = forms.CharField(max_length=64, required=True)
