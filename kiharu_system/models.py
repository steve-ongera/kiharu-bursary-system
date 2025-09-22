from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import MinValueValidator, MaxValueValidator, RegexValidator
import uuid

class User(AbstractUser):
    """
    Extended User model for authentication
    """
    USER_TYPES = (
        ('applicant', 'Applicant'),
        ('admin', 'Administrator'),
        ('reviewer', 'Application Reviewer'),
        ('finance', 'Finance Officer'),
    )
    
    user_type = models.CharField(max_length=20, choices=USER_TYPES, default='applicant')
    id_number = models.CharField(max_length=20, unique=True, null=True, blank=True)
    phone_regex = RegexValidator(
        regex=r'^\+254\d{9}$',
        message="Phone number must be entered in the format: '+254XXXXXXXXX'. Exactly 12 digits including country code."
    )
    phone_number = models.CharField(validators=[phone_regex], max_length=17, blank=True)
    
    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.user_type})"
    

# Add these models to your existing models.py file

from django.utils import timezone
from datetime import timedelta
import random
import string

class LoginAttempt(models.Model):
    """
    Track login attempts for security purposes
    """
    username = models.CharField(max_length=150)
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    success = models.BooleanField(default=False)
    user_agent = models.TextField(blank=True, null=True)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"Login attempt for {self.username} at {self.timestamp}"

class AccountLock(models.Model):
    """
    Track locked accounts
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='account_lock')
    locked_at = models.DateTimeField(auto_now_add=True)
    failed_attempts = models.PositiveIntegerField(default=0)
    last_attempt_ip = models.GenericIPAddressField()
    unlock_time = models.DateTimeField(null=True, blank=True)
    is_locked = models.BooleanField(default=True)
    
    def is_account_locked(self):
        if not self.is_locked:
            return False
        if self.unlock_time and timezone.now() > self.unlock_time:
            self.is_locked = False
            self.save()
            return False
        return True
    
    def __str__(self):
        return f"Account lock for {self.user.username}"

class TwoFactorCode(models.Model):
    """
    Store 2FA verification codes
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='tfa_codes')
    code = models.CharField(max_length=7)  # Format: XXX-XXX
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)
    used_at = models.DateTimeField(null=True, blank=True)
    ip_address = models.GenericIPAddressField()
    session_key = models.CharField(max_length=40)  # To link with session
    
    def save(self, *args, **kwargs):
        if not self.code:
            # Generate 6-digit code in XXX-XXX format
            digits = ''.join(random.choices(string.digits, k=6))
            self.code = f"{digits[:3]}-{digits[3:]}"
        
        if not self.expires_at:
            # Set expiration to 2 minutes from creation
            self.expires_at = timezone.now() + timedelta(minutes=2)
        
        super().save(*args, **kwargs)
    
    def is_expired(self):
        return timezone.now() > self.expires_at
    
    def is_valid(self):
        return not self.used and not self.is_expired()
    
    def mark_as_used(self):
        self.used = True
        self.used_at = timezone.now()
        self.save()
    
    def time_remaining(self):
        """Return seconds remaining before expiration"""
        if self.is_expired():
            return 0
        return int((self.expires_at - timezone.now()).total_seconds())
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"2FA Code for {self.user.username} - {self.code}"

class SecurityNotification(models.Model):
    """
    Security-related notifications sent to users
    """
    NOTIFICATION_TYPES = (
        ('failed_login', 'Failed Login Attempt'),
        ('account_locked', 'Account Locked'),
        ('tfa_code', '2FA Code'),
        ('successful_login', 'Successful Login'),
        ('account_unlocked', 'Account Unlocked'),
    )
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='security_notifications')
    notification_type = models.CharField(max_length=20, choices=NOTIFICATION_TYPES)
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    message = models.TextField()
    email_sent = models.BooleanField(default=False)
    email_sent_at = models.DateTimeField(null=True, blank=True)
    
    def __str__(self):
        return f"{self.get_notification_type_display()} for {self.user.username}"

class Ward(models.Model):
    """
    Administrative wards in Kiharu Constituency
    """
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    
    def __str__(self):
        return self.name

class Location(models.Model):
    """
    Locations within wards
    """
    name = models.CharField(max_length=100)
    ward = models.ForeignKey(Ward, on_delete=models.CASCADE, related_name='locations')
    
    def __str__(self):
        return f"{self.name}, {self.ward.name}"

class SubLocation(models.Model):
    """
    Sub-locations within locations
    """
    name = models.CharField(max_length=100)
    location = models.ForeignKey(Location, on_delete=models.CASCADE, related_name='sublocations')
    
    def __str__(self):
        return f"{self.name}, {self.location.name}"

class Village(models.Model):
    """
    Villages within sub-locations
    """
    name = models.CharField(max_length=100)
    sublocation = models.ForeignKey(SubLocation, on_delete=models.CASCADE, related_name='villages')
    
    def __str__(self):
        return f"{self.name}, {self.sublocation.name}"

class Institution(models.Model):
    """
    Educational institutions where applicants study
    """
    INSTITUTION_TYPES = (
        ('highschool', 'High School'),
        ('special_school', 'Special School'),
        ('college', 'College'),
        ('university', 'University'),
    )
    
    name = models.CharField(max_length=200)
    institution_type = models.CharField(max_length=20, choices=INSTITUTION_TYPES)
    county = models.CharField(max_length=100)
    postal_address = models.CharField(max_length=100, blank=True, null=True)
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    email = models.EmailField(blank=True, null=True)
    
    def __str__(self):
        return f"{self.name} ({self.get_institution_type_display()})"

class FiscalYear(models.Model):
    """
    Fiscal/Budget years for bursary allocations
    """
    name = models.CharField(max_length=20)  # e.g., "2024-2025"
    start_date = models.DateField()
    end_date = models.DateField()
    total_allocation = models.DecimalField(max_digits=12, decimal_places=2)
    is_active = models.BooleanField(default=False)
    
    def __str__(self):
        return self.name

class BursaryCategory(models.Model):
    """
    Categories for bursary allocation with specific budgets
    """
    CATEGORY_TYPES = (
        ('highschool', 'High School'),
        ('special_school', 'Special School'),
        ('college', 'College'),
        ('university', 'University'),
    )
    
    name = models.CharField(max_length=100)
    category_type = models.CharField(max_length=20, choices=CATEGORY_TYPES)
    fiscal_year = models.ForeignKey(FiscalYear, on_delete=models.CASCADE, related_name='categories')
    allocation_amount = models.DecimalField(max_digits=12, decimal_places=2)
    max_amount_per_applicant = models.DecimalField(max_digits=10, decimal_places=2)
    
    def __str__(self):
        return f"{self.name} - {self.fiscal_year.name}"

class Applicant(models.Model):
    """
    Applicant personal and demographic information
    """
    GENDER_CHOICES = (
        ('M', 'Male'),
        ('F', 'Female'),
       
    )
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='applicant_profile')
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES)
    date_of_birth = models.DateField()
    id_number = models.CharField(max_length=20, unique=True)
    ward = models.ForeignKey(Ward, on_delete=models.SET_NULL, null=True, related_name='residents')
    location = models.ForeignKey(Location, on_delete=models.SET_NULL, null=True)
    sublocation = models.ForeignKey(SubLocation, on_delete=models.SET_NULL, null=True)
    village = models.ForeignKey(Village, on_delete=models.SET_NULL, null=True)
    physical_address = models.TextField()
    postal_address = models.CharField(max_length=100, blank=True, null=True)
    special_needs = models.BooleanField(default=False)
    special_needs_description = models.TextField(blank=True, null=True)
    
    def __str__(self):
        return f"{self.user.first_name} {self.user.last_name}"

class Guardian(models.Model):
    """
    Parent/Guardian information for applicants
    """
    RELATIONSHIP_CHOICES = (
        ('father', 'Father'),
        ('mother', 'Mother'),
        ('guardian', 'Guardian'),
        
    )
    
    applicant = models.ForeignKey(Applicant, on_delete=models.CASCADE, related_name='guardians')
    name = models.CharField(max_length=200)
    relationship = models.CharField(max_length=20, choices=RELATIONSHIP_CHOICES)
    phone_number = models.CharField(max_length=20)
    email = models.EmailField(blank=True, null=True)
    occupation = models.CharField(max_length=200, blank=True, null=True)
    monthly_income = models.DecimalField(max_digits=12, decimal_places=2, blank=True, null=True)
    id_number = models.CharField(max_length=20, blank=True, null=True)
    
    def __str__(self):
        return f"{self.name} ({self.get_relationship_display()} of {self.applicant})"

class SiblingInformation(models.Model):
    """
    Information about siblings of the applicant
    """
    applicant = models.ForeignKey(Applicant, on_delete=models.CASCADE, related_name='siblings')
    name = models.CharField(max_length=200)
    age = models.PositiveIntegerField()
    education_level = models.CharField(max_length=100)
    school_name = models.CharField(max_length=200, blank=True, null=True)
    
    def __str__(self):
        return f"{self.name} (Sibling of {self.applicant})"

class Application(models.Model):
    """
    Bursary application details
    """
    APPLICATION_STATUS = (
        ('draft', 'Draft'),
        ('submitted', 'Submitted'),
        ('under_review', 'Under Review'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('disbursed', 'Disbursed'),
    )
    
    application_number = models.CharField(max_length=20, unique=True, editable=False)
    applicant = models.ForeignKey(Applicant, on_delete=models.CASCADE, related_name='applications')
    fiscal_year = models.ForeignKey(FiscalYear, on_delete=models.CASCADE)
    bursary_category = models.ForeignKey(BursaryCategory, on_delete=models.CASCADE)
    institution = models.ForeignKey(Institution, on_delete=models.CASCADE)
    status = models.CharField(max_length=20, choices=APPLICATION_STATUS, default='draft')
    
    # Academic Information
    admission_number = models.CharField(max_length=100)
    year_of_study = models.PositiveIntegerField()
    course_name = models.CharField(max_length=200, blank=True, null=True)  # For college/university
    expected_completion_date = models.DateField()
    
    # Financial Information
    total_fees_payable = models.DecimalField(max_digits=10, decimal_places=2)
    fees_paid = models.DecimalField(max_digits=10, decimal_places=2)
    fees_balance = models.DecimalField(max_digits=10, decimal_places=2)
    amount_requested = models.DecimalField(max_digits=10, decimal_places=2)
    
    # Other bursaries received
    other_bursaries = models.BooleanField(default=False)
    other_bursaries_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    other_bursaries_source = models.CharField(max_length=200, blank=True, null=True)
    
    # Family situation
    is_orphan = models.BooleanField(default=False)
    is_disabled = models.BooleanField(default=False)
    has_chronic_illness = models.BooleanField(default=False)
    chronic_illness_description = models.TextField(blank=True, null=True)
    
    # Application dates
    date_submitted = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    
    # Previous allocations
    previous_allocation = models.BooleanField(default=False)
    previous_allocation_year = models.CharField(max_length=20, blank=True, null=True)
    previous_allocation_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    
    # Attachments and other information will be related through foreign keys
    
    def save(self, *args, **kwargs):
        if not self.application_number:
            # Generate a unique application number
            year = self.fiscal_year.name.split('-')[0]
            random_string = uuid.uuid4().hex[:6].upper()
            self.application_number = f"KB-{year}-{random_string}"
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.application_number} - {self.applicant}"

class Document(models.Model):
    """
    Supporting documents for applications
    """
    DOCUMENT_TYPES = (
        ('id_card', 'National ID Card'),
        ('admission_letter', 'Admission Letter'),
        ('fee_structure', 'Fee Structure'),
        ('fee_statement', 'Fee Statement'),
        ('academic_results', 'Academic Results'),
        ('birth_certificate', 'Birth Certificate'),
        ('parent_id', 'Parent/Guardian ID'),
        ('death_certificate', 'Death Certificate'),
        ('medical_report', 'Medical Report'),
        ('recommendation_letter', 'Recommendation Letter'),
        ('other', 'Other Document'),
    )
    
    application = models.ForeignKey(Application, on_delete=models.CASCADE, related_name='documents')
    document_type = models.CharField(max_length=30, choices=DOCUMENT_TYPES)
    file = models.FileField(upload_to='bursary_documents/')
    description = models.CharField(max_length=200, blank=True, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.get_document_type_display()} - {self.application.application_number}"

class Review(models.Model):
    """
    Reviews and comments on applications
    """
    application = models.ForeignKey(Application, on_delete=models.CASCADE, related_name='reviews')
    reviewer = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='reviews')
    comments = models.TextField()
    recommendation = models.CharField(max_length=50, choices=[
        ('approve', 'Approve'),
        ('reject', 'Reject'),
        ('more_info', 'Request More Information')
    ])
    recommended_amount = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    review_date = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Review for {self.application.application_number} by {self.reviewer.username}"

class Allocation(models.Model):
    """
    Approved bursary allocations
    """
    application = models.OneToOneField(Application, on_delete=models.CASCADE, related_name='allocation')
    amount_allocated = models.DecimalField(max_digits=10, decimal_places=2)
    allocation_date = models.DateField(auto_now_add=True)
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='approvals')
    cheque_number = models.CharField(max_length=50, blank=True, null=True)
    is_disbursed = models.BooleanField(default=False)
    disbursement_date = models.DateField(blank=True, null=True)
    disbursed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='disbursements')
    remarks = models.TextField(blank=True, null=True)
    
    def __str__(self):
        return f"Allocation for {self.application.application_number}: KES {self.amount_allocated}"

class Notification(models.Model):
    """
    System notifications for users
    """
    NOTIFICATION_TYPES = (
        ('application_status', 'Application Status'),
        ('document_request', 'Document Request'),
        ('allocation', 'Allocation'),
        ('disbursement', 'Disbursement'),
        ('system', 'System Notification'),
    )
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    notification_type = models.CharField(max_length=20, choices=NOTIFICATION_TYPES)
    title = models.CharField(max_length=200)
    message = models.TextField()
    related_application = models.ForeignKey(Application, on_delete=models.SET_NULL, null=True, blank=True)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.title} for {self.user.username}"

class SMSLog(models.Model):
    """
    Log of SMS messages sent to users
    """
    recipient = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='sms_messages')
    phone_number = models.CharField(max_length=20)
    message = models.TextField()
    related_application = models.ForeignKey(Application, on_delete=models.SET_NULL, null=True, blank=True)
    status = models.CharField(max_length=20, default='pending')
    sent_at = models.DateTimeField(auto_now_add=True)
    delivery_status = models.CharField(max_length=20, blank=True, null=True)
    
    def __str__(self):
        return f"SMS to {self.phone_number} at {self.sent_at}"

class AuditLog(models.Model):
    """
    System audit trail
    """
    ACTION_TYPES = (
        ('create', 'Create'),
        ('update', 'Update'),
        ('delete', 'Delete'),
        ('view', 'View'),
        ('approve', 'Approve'),
        ('reject', 'Reject'),
        ('disburse', 'Disburse'),
        ('login', 'Login'),
        ('logout', 'Logout'),
    )
    
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='audit_logs')
    action = models.CharField(max_length=20, choices=ACTION_TYPES)
    table_affected = models.CharField(max_length=100)
    record_id = models.CharField(max_length=100, blank=True, null=True)
    description = models.TextField()
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.action} by {self.user} on {self.timestamp}"

class SystemSettings(models.Model):
    """
    Configuration settings for the system
    """
    setting_name = models.CharField(max_length=100, unique=True)
    setting_value = models.TextField()
    description = models.TextField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    last_updated = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    
    def __str__(self):
        return self.setting_name

class FAQ(models.Model):
    """
    Frequently Asked Questions
    """
    question = models.CharField(max_length=500)
    answer = models.TextField()
    category = models.CharField(max_length=100, default='General')
    is_active = models.BooleanField(default=True)
    order = models.PositiveIntegerField(default=0)
    
    def __str__(self):
        return self.question

class Announcement(models.Model):
    """
    Public announcements for applicants
    """
    title = models.CharField(max_length=200)
    content = models.TextField()
    published_date = models.DateTimeField()
    expiry_date = models.DateTimeField()
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    
    def __str__(self):
        return self.title