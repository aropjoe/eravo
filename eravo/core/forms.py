from django import forms


class ScanForm(forms.Form):
    sha256 = forms.CharField(max_length=64, required=True)


class SecurityReportForm(forms.Form):
    target_type = forms.ChoiceField(
        choices=[
            ("file", "File"),
            ("url", "URL"),
            ("domain", "Domain"),
            ("ip", "IP Address"),
        ]
    )
    target_value = forms.CharField(max_length=255)


class IncidentForm(forms.ModelForm):
    class Meta:
        model = Incident
        fields = ("description", "status")


class MaliciousItemForm(forms.ModelForm):
    class Meta:
        model = MaliciousItem
        fields = ("item_type", "value", "detection_result")


class IOCSearchForm(forms.ModelForm):
    class Meta:
        model = IOCSearch
        fields = ('query',)