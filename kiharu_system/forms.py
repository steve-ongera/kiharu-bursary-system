from django import forms
from .models import Applicant, Application, Document, Guardian, SiblingInformation


class BootstrapModelForm(forms.ModelForm):
    """
    Base form to add Bootstrap 'form-control' class to all fields
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            if not isinstance(field.widget, forms.CheckboxInput):  # don't override checkboxes
                field.widget.attrs.update({'class': 'form-control'})


class ApplicantForm(BootstrapModelForm):
    class Meta:
        model = Applicant
        exclude = ['user']  # user is set in the view
        widgets = {
            'date_of_birth': forms.DateInput(attrs={'type': 'date'}),
            'special_needs_description': forms.Textarea(attrs={'rows': 3}),
            'physical_address': forms.Textarea(attrs={'rows': 2}),
        }


class ApplicationForm(BootstrapModelForm):
    class Meta:
        model = Application
        exclude = ['applicant', 'fiscal_year', 'status', 'application_number', 'date_submitted', 'last_updated']
        widgets = {
            'expected_completion_date': forms.DateInput(attrs={'type': 'date'}),
            'course_name': forms.TextInput(attrs={'placeholder': 'e.g. Bachelor of Commerce'}),
        }


class DocumentForm(BootstrapModelForm):
    class Meta:
        model = Document
        fields = ['document_type', 'file', 'description']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 2}),
        }


class GuardianForm(BootstrapModelForm):
    class Meta:
        model = Guardian
        exclude = ['applicant']


class SiblingForm(BootstrapModelForm):
    class Meta:
        model = SiblingInformation
        exclude = ['applicant']
