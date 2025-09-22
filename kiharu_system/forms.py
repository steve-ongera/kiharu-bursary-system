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


from django import forms
from .models import Application, BursaryCategory, Institution, FiscalYear

class ApplicationForm(forms.ModelForm):
    class Meta:
        model = Application
        fields = [
            'bursary_category', 'institution', 'admission_number', 'year_of_study',
            'course_name', 'expected_completion_date', 'total_fees_payable',
            'fees_paid', 'amount_requested', 'other_bursaries', 'other_bursaries_amount',
            'other_bursaries_source', 'previous_allocation', 'previous_allocation_year',
            'previous_allocation_amount', 'is_orphan', 'is_disabled', 'has_chronic_illness',
            'chronic_illness_description'
        ]
        widgets = {
            'bursary_category': forms.Select(attrs={
                'class': 'form-select',
                'required': True
            }),
            'institution': forms.Select(attrs={
                'class': 'form-select',
                'required': True
            }),
            'admission_number': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter your admission number',
                'required': True
            }),
            'year_of_study': forms.NumberInput(attrs={
                'class': 'form-control',
                'min': 1,
                'max': 10,
                'required': True
            }),
            'course_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter course name (for college/university)'
            }),
            'expected_completion_date': forms.DateInput(attrs={
                'class': 'form-control',
                'type': 'date',
                'required': True
            }),
            'total_fees_payable': forms.NumberInput(attrs={
                'class': 'form-control',
                'step': '0.01',
                'min': '0',
                'placeholder': '0.00',
                'required': True
            }),
            'fees_paid': forms.NumberInput(attrs={
                'class': 'form-control',
                'step': '0.01',
                'min': '0',
                'placeholder': '0.00',
                'required': True
            }),
            'amount_requested': forms.NumberInput(attrs={
                'class': 'form-control',
                'step': '0.01',
                'min': '0',
                'placeholder': '0.00',
                'required': True
            }),
            'other_bursaries': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            }),
            'other_bursaries_amount': forms.NumberInput(attrs={
                'class': 'form-control',
                'step': '0.01',
                'min': '0',
                'placeholder': '0.00'
            }),
            'other_bursaries_source': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Source of other bursary'
            }),
            'previous_allocation': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            }),
            'previous_allocation_year': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'e.g., 2023-2024'
            }),
            'previous_allocation_amount': forms.NumberInput(attrs={
                'class': 'form-control',
                'step': '0.01',
                'min': '0',
                'placeholder': '0.00'
            }),
            'is_orphan': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            }),
            'is_disabled': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            }),
            'has_chronic_illness': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            }),
            'chronic_illness_description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Please describe the chronic illness'
            }),
        }

    def __init__(self, *args, **kwargs):
        fiscal_year = kwargs.pop('fiscal_year', None)
        super().__init__(*args, **kwargs)
        
        if fiscal_year:
            self.fields['bursary_category'].queryset = BursaryCategory.objects.filter(
                fiscal_year=fiscal_year
            )
        
        # Set default values for optional numeric fields
        if not self.instance.pk:
            self.fields['other_bursaries_amount'].initial = 0
            self.fields['previous_allocation_amount'].initial = 0

    def clean_amount_requested(self):
        amount_requested = self.cleaned_data.get('amount_requested')
        bursary_category = self.cleaned_data.get('bursary_category')
        
        if amount_requested and bursary_category:
            if amount_requested > bursary_category.max_amount_per_applicant:
                raise forms.ValidationError(
                    f'Amount requested cannot exceed {bursary_category.max_amount_per_applicant} '
                    f'for this category.'
                )
        return amount_requested

    def clean_fees_paid(self):
        fees_paid = self.cleaned_data.get('fees_paid')
        total_fees_payable = self.cleaned_data.get('total_fees_payable')
        
        if fees_paid and total_fees_payable:
            if fees_paid > total_fees_payable:
                raise forms.ValidationError(
                    'Fees paid cannot be greater than total fees payable.'
                )
        return fees_paid

    def clean(self):
        cleaned_data = super().clean()
        
        # Validate other bursaries fields
        other_bursaries = cleaned_data.get('other_bursaries')
        other_bursaries_amount = cleaned_data.get('other_bursaries_amount')
        other_bursaries_source = cleaned_data.get('other_bursaries_source')
        
        if other_bursaries:
            if not other_bursaries_amount or other_bursaries_amount <= 0:
                self.add_error('other_bursaries_amount', 
                             'Please enter the amount of other bursaries received.')
            if not other_bursaries_source:
                self.add_error('other_bursaries_source', 
                             'Please specify the source of other bursaries.')
        
        # Validate previous allocation fields
        previous_allocation = cleaned_data.get('previous_allocation')
        previous_allocation_year = cleaned_data.get('previous_allocation_year')
        previous_allocation_amount = cleaned_data.get('previous_allocation_amount')
        
        if previous_allocation:
            if not previous_allocation_year:
                self.add_error('previous_allocation_year', 
                             'Please enter the year of previous allocation.')
            if not previous_allocation_amount or previous_allocation_amount <= 0:
                self.add_error('previous_allocation_amount', 
                             'Please enter the amount of previous allocation.')
        
        # Validate chronic illness description
        has_chronic_illness = cleaned_data.get('has_chronic_illness')
        chronic_illness_description = cleaned_data.get('chronic_illness_description')
        
        if has_chronic_illness and not chronic_illness_description:
            self.add_error('chronic_illness_description', 
                         'Please describe the chronic illness.')
        
        return cleaned_data


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


from django import forms
from django.contrib.auth.forms import UserChangeForm
from .models import User, SystemSettings, FAQ, Announcement, Notification

class AdminProfileForm(UserChangeForm):
    """Form for admin profile settings"""
    
    class Meta:
        model = User
        fields = [
            'first_name', 'last_name', 'email', 'phone_number', 
            'id_number', 'user_type', 'is_active'
        ]
        widgets = {
            'first_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter first name'
            }),
            'last_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter last name'
            }),
            'email': forms.EmailInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter email address'
            }),
            'phone_number': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': '+254XXXXXXXXX'
            }),
            'id_number': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter ID number'
            }),
            'user_type': forms.Select(attrs={
                'class': 'form-control'
            }),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Remove password field from the form
        if 'password' in self.fields:
            del self.fields['password']
        
        # Make certain fields required
        self.fields['first_name'].required = True
        self.fields['last_name'].required = True
        self.fields['email'].required = True

class SystemSettingsForm(forms.ModelForm):
    """Form for system settings"""
    
    class Meta:
        model = SystemSettings
        fields = ['setting_name', 'setting_value', 'description']
        widgets = {
            'setting_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Setting name (e.g., max_application_amount)'
            }),
            'setting_value': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Setting value'
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 2,
                'placeholder': 'Brief description of this setting'
            }),
        }

class FAQForm(forms.ModelForm):
    """Form for FAQ management"""
    
    class Meta:
        model = FAQ
        fields = ['question', 'answer', 'category', 'order', 'is_active']
        widgets = {
            'question': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter the question'
            }),
            'answer': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Enter the answer'
            }),
            'category': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Category (e.g., General, Applications, etc.)'
            }),
            'order': forms.NumberInput(attrs={
                'class': 'form-control',
                'placeholder': 'Display order'
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            }),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['question'].required = True
        self.fields['answer'].required = True
        self.fields['category'].initial = 'General'
        self.fields['order'].initial = 0

class AnnouncementForm(forms.ModelForm):
    """Form for announcements"""
    
    class Meta:
        model = Announcement
        fields = ['title', 'content', 'published_date', 'expiry_date', 'is_active']
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Announcement title'
            }),
            'content': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 5,
                'placeholder': 'Announcement content'
            }),
            'published_date': forms.DateTimeInput(attrs={
                'class': 'form-control',
                'type': 'datetime-local'
            }),
            'expiry_date': forms.DateTimeInput(attrs={
                'class': 'form-control',
                'type': 'datetime-local'
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            }),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['title'].required = True
        self.fields['content'].required = True
        self.fields['published_date'].required = True
        self.fields['expiry_date'].required = True

class NotificationForm(forms.ModelForm):
    """Form for sending notifications"""
    
    # Custom field for selecting multiple users
    users = forms.ModelMultipleChoiceField(
        queryset=User.objects.all(),
        widget=forms.CheckboxSelectMultiple(attrs={
            'class': 'form-check-input'
        }),
        required=False,
        help_text="Account lockout duration in minutes"
    )
    
    password_min_length = forms.IntegerField(
        min_value=6,
        max_value=20,
        initial=8,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'placeholder': 'Minimum password length'
        }),
        help_text="Minimum required password length"
    )
    
    require_special_characters = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-check-input'
        }),
        help_text="Require special characters in passwords"
    )
    
    enable_two_factor = forms.BooleanField(
        required=False,
        initial=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-check-input'
        }),
        help_text="Enable two-factor authentication"
    )
    
    
    class Meta:
        model = Notification
        fields = ['notification_type', 'title', 'message']
        widgets = {
            'notification_type': forms.Select(attrs={
                'class': 'form-control'
            }),
            'title': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Notification title'
            }),
            'message': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Notification message'
            }),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['title'].required = True
        self.fields['message'].required = True
        
        # Filter users to show only applicants and staff
        self.fields['users'].queryset = User.objects.filter(
            is_active=True
        ).order_by('first_name', 'last_name')

    def save(self, commit=True):
        """Override save to handle multiple users"""
        notification = super().save(commit=False)
        
        if commit:
            selected_users = self.cleaned_data.get('users')
            if selected_users:
                # Create notification for selected users
                notifications = []
                for user in selected_users:
                    notifications.append(Notification(
                        user=user,
                        notification_type=notification.notification_type,
                        title=notification.title,
                        message=notification.message,
                    ))
                Notification.objects.bulk_create(notifications)
                return notifications[0] if notifications else None
            else:
                # Create notification for all users
                all_users = User.objects.filter(is_active=True)
                notifications = []
                for user in all_users:
                    notifications.append(Notification(
                        user=user,
                        notification_type=notification.notification_type,
                        title=notification.title,
                        message=notification.message,
                    ))
                Notification.objects.bulk_create(notifications)
                return notifications[0] if notifications else None
        
        return notification

# Additional forms for bulk operations
class BulkNotificationForm(forms.Form):
    """Form for sending bulk notifications"""
    
    USER_TYPE_CHOICES = [
        ('all', 'All Users'),
        ('applicant', 'Applicants Only'),
        ('admin', 'Administrators'),
        ('reviewer', 'Reviewers'),
        ('finance', 'Finance Officers'),
    ]
    
    user_type = forms.ChoiceField(
        choices=USER_TYPE_CHOICES,
        widget=forms.Select(attrs={'class': 'form-control'}),
        initial='all'
    )
    
    notification_type = forms.ChoiceField(
        choices=Notification.NOTIFICATION_TYPES,
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    
    title = forms.CharField(
        max_length=200,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Notification title'
        })
    )
    
    message = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 4,
            'placeholder': 'Notification message'
        })
    )

class SecuritySettingsForm(forms.Form):
    """Form for security settings"""
    
    session_timeout = forms.IntegerField(
        min_value=15,
        max_value=480,
        initial=60,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'placeholder': 'Session timeout in minutes'
        }),
        help_text="Session timeout in minutes (15-480)"
    )
    
    max_login_attempts = forms.IntegerField(
        min_value=3,
        max_value=10,
        initial=5,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'placeholder': 'Maximum login attempts'
        }),
        help_text="Maximum failed login attempts before account lockout"
    )
    
    lockout_duration = forms.IntegerField(
        min_value=5,
        max_value=60,
        initial=15,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'placeholder': 'Lockout duration in minutes'
        }),
        help_text="Account lockout duration in minutes"
    )
       

from django import forms
from .models import BursaryCategory

class BursaryCategoryForm(forms.ModelForm):
    class Meta:
        model = BursaryCategory
        fields = ['name', 'category_type', 'fiscal_year', 'allocation_amount', 'max_amount_per_applicant']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'category_type': forms.Select(attrs={'class': 'form-control'}),
            'fiscal_year': forms.Select(attrs={'class': 'form-control'}),
            'allocation_amount': forms.NumberInput(attrs={'class': 'form-control'}),
            'max_amount_per_applicant': forms.NumberInput(attrs={'class': 'form-control'}),
        }
