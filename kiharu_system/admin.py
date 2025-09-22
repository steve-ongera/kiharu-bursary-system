from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe
from .models import *


class CustomUserAdmin(BaseUserAdmin):
    """Custom user admin to handle the extended User model"""
    list_display = ('username', 'email', 'first_name', 'last_name', 'user_type', 'is_staff', 'date_joined')
    list_filter = ('user_type', 'is_staff', 'is_superuser', 'is_active', 'date_joined')
    search_fields = ('username', 'email', 'first_name', 'last_name', 'id_number', 'phone_number')
    ordering = ('username',)
    
    fieldsets = BaseUserAdmin.fieldsets + (
        ('Additional Info', {
            'fields': ('user_type', 'id_number', 'phone_number')
        }),
    )
    
    add_fieldsets = BaseUserAdmin.add_fieldsets + (
        ('Additional Info', {
            'fields': ('user_type', 'id_number', 'phone_number')
        }),
    )


class LocationInline(admin.TabularInline):
    model = Location
    extra = 1


class SubLocationInline(admin.TabularInline):
    model = SubLocation
    extra = 1


class VillageInline(admin.TabularInline):
    model = Village
    extra = 1


@admin.register(Ward)
class WardAdmin(admin.ModelAdmin):
    list_display = ('name', 'location_count', 'description')
    search_fields = ('name',)
    inlines = [LocationInline]
    
    def location_count(self, obj):
        return obj.locations.count()
    location_count.short_description = 'Locations'


@admin.register(Location)
class LocationAdmin(admin.ModelAdmin):
    list_display = ('name', 'ward', 'sublocation_count')
    list_filter = ('ward',)
    search_fields = ('name', 'ward__name')
    inlines = [SubLocationInline]
    
    def sublocation_count(self, obj):
        return obj.sublocations.count()
    sublocation_count.short_description = 'Sub-locations'


@admin.register(SubLocation)
class SubLocationAdmin(admin.ModelAdmin):
    list_display = ('name', 'location', 'village_count')
    list_filter = ('location__ward',)
    search_fields = ('name', 'location__name', 'location__ward__name')
    inlines = [VillageInline]
    
    def village_count(self, obj):
        return obj.villages.count()
    village_count.short_description = 'Villages'


@admin.register(Village)
class VillageAdmin(admin.ModelAdmin):
    list_display = ('name', 'sublocation', 'location', 'ward')
    list_filter = ('sublocation__location__ward',)
    search_fields = ('name', 'sublocation__name', 'sublocation__location__name')
    
    def location(self, obj):
        return obj.sublocation.location.name
    location.short_description = 'Location'
    
    def ward(self, obj):
        return obj.sublocation.location.ward.name
    ward.short_description = 'Ward'


@admin.register(Institution)
class InstitutionAdmin(admin.ModelAdmin):
    list_display = ('name', 'institution_type', 'county', 'phone_number', 'email')
    list_filter = ('institution_type', 'county')
    search_fields = ('name', 'county')


class BursaryCategoryInline(admin.TabularInline):
    model = BursaryCategory
    extra = 1
    fields = ('name', 'category_type', 'allocation_amount', 'max_amount_per_applicant')


@admin.register(FiscalYear)
class FiscalYearAdmin(admin.ModelAdmin):
    list_display = ('name', 'start_date', 'end_date', 'total_allocation', 'is_active')
    list_filter = ('is_active',)
    search_fields = ('name',)
    inlines = [BursaryCategoryInline]
    
    def get_readonly_fields(self, request, obj=None):
        if obj:  # Editing existing object
            return self.readonly_fields + ('name',)
        return self.readonly_fields


@admin.register(BursaryCategory)
class BursaryCategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'category_type', 'fiscal_year', 'allocation_amount', 'max_amount_per_applicant')
    list_filter = ('category_type', 'fiscal_year')
    search_fields = ('name', 'fiscal_year__name')


class GuardianInline(admin.TabularInline):
    model = Guardian
    extra = 1
    fields = ('name', 'relationship', 'phone_number', 'occupation', 'monthly_income')


class SiblingInformationInline(admin.TabularInline):
    model = SiblingInformation
    extra = 1
    fields = ('name', 'age', 'education_level', 'school_name')


@admin.register(Applicant)
class ApplicantAdmin(admin.ModelAdmin):
    list_display = ('full_name', 'gender', 'date_of_birth', 'ward', 'village', 'special_needs')
    list_filter = ('gender', 'ward', 'special_needs')
    search_fields = ('user__first_name', 'user__last_name', 'id_number', 'user__phone_number')
    inlines = [GuardianInline, SiblingInformationInline]
    
    def full_name(self, obj):
        return f"{obj.user.first_name} {obj.user.last_name}"
    full_name.short_description = 'Full Name'


@admin.register(Guardian)
class GuardianAdmin(admin.ModelAdmin):
    list_display = ('name', 'relationship', 'applicant', 'phone_number', 'occupation', 'monthly_income')
    list_filter = ('relationship',)
    search_fields = ('name', 'applicant__user__first_name', 'applicant__user__last_name')


class DocumentInline(admin.TabularInline):
    model = Document
    extra = 1
    fields = ('document_type', 'file', 'description')
    readonly_fields = ('uploaded_at',)


class ReviewInline(admin.TabularInline):
    model = Review
    extra = 0
    fields = ('reviewer', 'recommendation', 'recommended_amount', 'comments')
    readonly_fields = ('review_date',)


@admin.register(Application)
class ApplicationAdmin(admin.ModelAdmin):
    list_display = ('application_number', 'applicant_name', 'status', 'bursary_category', 'amount_requested', 'date_submitted')
    list_filter = ('status', 'bursary_category__category_type', 'fiscal_year', 'is_orphan', 'is_disabled')
    search_fields = ('application_number', 'applicant__user__first_name', 'applicant__user__last_name')
    readonly_fields = ('application_number', 'date_submitted', 'last_updated')
    inlines = [DocumentInline, ReviewInline]
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('application_number', 'applicant', 'fiscal_year', 'bursary_category', 'status')
        }),
        ('Academic Information', {
            'fields': ('institution', 'admission_number', 'year_of_study', 'course_name', 'expected_completion_date')
        }),
        ('Financial Information', {
            'fields': ('total_fees_payable', 'fees_paid', 'fees_balance', 'amount_requested')
        }),
        ('Other Bursaries', {
            'fields': ('other_bursaries', 'other_bursaries_amount', 'other_bursaries_source')
        }),
        ('Family Situation', {
            'fields': ('is_orphan', 'is_disabled', 'has_chronic_illness', 'chronic_illness_description')
        }),
        ('Previous Allocations', {
            'fields': ('previous_allocation', 'previous_allocation_year', 'previous_allocation_amount')
        }),
        ('Timestamps', {
            'fields': ('date_submitted', 'last_updated'),
            'classes': ('collapse',)
        })
    )
    
    def applicant_name(self, obj):
        return f"{obj.applicant.user.first_name} {obj.applicant.user.last_name}"
    applicant_name.short_description = 'Applicant'
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related(
            'applicant__user', 'bursary_category', 'fiscal_year', 'institution'
        )


@admin.register(Document)
class DocumentAdmin(admin.ModelAdmin):
    list_display = ('document_type', 'application_number', 'applicant_name', 'uploaded_at')
    list_filter = ('document_type', 'uploaded_at')
    search_fields = ('application__application_number', 'application__applicant__user__first_name')
    readonly_fields = ('uploaded_at',)
    
    def application_number(self, obj):
        return obj.application.application_number
    application_number.short_description = 'Application'
    
    def applicant_name(self, obj):
        return f"{obj.application.applicant.user.first_name} {obj.application.applicant.user.last_name}"
    applicant_name.short_description = 'Applicant'


@admin.register(Review)
class ReviewAdmin(admin.ModelAdmin):
    list_display = ('application_number', 'reviewer', 'recommendation', 'recommended_amount', 'review_date')
    list_filter = ('recommendation', 'review_date')
    search_fields = ('application__application_number', 'reviewer__username')
    readonly_fields = ('review_date',)
    
    def application_number(self, obj):
        return obj.application.application_number
    application_number.short_description = 'Application'


@admin.register(Allocation)
class AllocationAdmin(admin.ModelAdmin):
    list_display = ('application_number', 'amount_allocated', 'allocation_date', 'is_disbursed', 'disbursement_date')
    list_filter = ('is_disbursed', 'allocation_date', 'disbursement_date')
    search_fields = ('application__application_number', 'cheque_number')
    readonly_fields = ('allocation_date',)
    
    fieldsets = (
        ('Allocation Details', {
            'fields': ('application', 'amount_allocated', 'allocation_date', 'approved_by')
        }),
        ('Disbursement', {
            'fields': ('is_disbursed', 'disbursement_date', 'disbursed_by', 'cheque_number', 'remarks')
        })
    )
    
    def application_number(self, obj):
        return obj.application.application_number
    application_number.short_description = 'Application'


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ('title', 'user', 'notification_type', 'is_read', 'created_at')
    list_filter = ('notification_type', 'is_read', 'created_at')
    search_fields = ('title', 'user__username', 'user__first_name', 'user__last_name')
    readonly_fields = ('created_at',)


@admin.register(SMSLog)
class SMSLogAdmin(admin.ModelAdmin):
    list_display = ('phone_number', 'recipient_name', 'status', 'delivery_status', 'sent_at')
    list_filter = ('status', 'delivery_status', 'sent_at')
    search_fields = ('phone_number', 'recipient__username', 'message')
    readonly_fields = ('sent_at',)
    
    def recipient_name(self, obj):
        if obj.recipient:
            return f"{obj.recipient.first_name} {obj.recipient.last_name}"
        return "Unknown"
    recipient_name.short_description = 'Recipient'


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'action', 'table_affected', 'timestamp', 'ip_address')
    list_filter = ('action', 'table_affected', 'timestamp')
    search_fields = ('user__username', 'description', 'record_id')
    readonly_fields = ('timestamp',)
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False


@admin.register(SystemSettings)
class SystemSettingsAdmin(admin.ModelAdmin):
    list_display = ('setting_name', 'is_active', 'last_updated', 'updated_by')
    list_filter = ('is_active', 'last_updated')
    search_fields = ('setting_name', 'description')
    readonly_fields = ('last_updated',)


@admin.register(FAQ)
class FAQAdmin(admin.ModelAdmin):
    list_display = ('question', 'category', 'is_active', 'order')
    list_filter = ('category', 'is_active')
    search_fields = ('question', 'answer', 'category')
    list_editable = ('is_active', 'order')


@admin.register(Announcement)
class AnnouncementAdmin(admin.ModelAdmin):
    list_display = ('title', 'published_date', 'expiry_date', 'is_active', 'created_by')
    list_filter = ('is_active', 'published_date', 'expiry_date')
    search_fields = ('title', 'content')
    readonly_fields = ('created_by',)
    
    def save_model(self, request, obj, form, change):
        if not change:  # If creating a new object
            obj.created_by = request.user
        super().save_model(request, obj, form, change)


# Security Models Admin
@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ('username', 'ip_address', 'timestamp', 'success', 'user_agent_short')
    list_filter = ('success', 'timestamp')
    search_fields = ('username', 'ip_address')
    readonly_fields = ('username', 'ip_address', 'timestamp', 'success', 'user_agent')
    ordering = ('-timestamp',)
    
    def user_agent_short(self, obj):
        if obj.user_agent and len(obj.user_agent) > 50:
            return obj.user_agent[:50] + '...'
        return obj.user_agent or 'N/A'
    user_agent_short.short_description = 'User Agent'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False

@admin.register(AccountLock)
class AccountLockAdmin(admin.ModelAdmin):
    list_display = ('user', 'is_locked', 'failed_attempts', 'locked_at', 'unlock_time', 'last_attempt_ip')
    list_filter = ('is_locked', 'locked_at')
    search_fields = ('user__username', 'user__email', 'last_attempt_ip')
    readonly_fields = ('locked_at', 'failed_attempts', 'last_attempt_ip')
    actions = ['unlock_accounts', 'reset_attempts']
    
    def unlock_accounts(self, request, queryset):
        updated = queryset.update(is_locked=False, unlock_time=None)
        self.message_user(request, f'{updated} account(s) unlocked successfully.')
    unlock_accounts.short_description = 'Unlock selected accounts'
    
    def reset_attempts(self, request, queryset):
        updated = queryset.update(failed_attempts=0, is_locked=False, unlock_time=None)
        self.message_user(request, f'{updated} account(s) reset successfully.')
    reset_attempts.short_description = 'Reset failed attempts'

@admin.register(TwoFactorCode)
class TwoFactorCodeAdmin(admin.ModelAdmin):
    list_display = ('user', 'code', 'created_at', 'expires_at', 'used', 'ip_address', 'is_expired_display')
    list_filter = ('used', 'created_at', 'expires_at')
    search_fields = ('user__username', 'user__email', 'code', 'ip_address')
    readonly_fields = ('user', 'code', 'created_at', 'expires_at', 'used', 'used_at', 'ip_address', 'session_key')
    ordering = ('-created_at',)
    
    def is_expired_display(self, obj):
        if obj.is_expired():
            return format_html('<span style="color: red;">Expired</span>')
        return format_html('<span style="color: green;">Valid</span>')
    is_expired_display.short_description = 'Status'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False

@admin.register(SecurityNotification)
class SecurityNotificationAdmin(admin.ModelAdmin):
    list_display = ('user', 'notification_type', 'timestamp', 'email_sent', 'ip_address')
    list_filter = ('notification_type', 'email_sent', 'timestamp')
    search_fields = ('user__username', 'user__email', 'ip_address')
    readonly_fields = ('user', 'notification_type', 'ip_address', 'timestamp', 'message', 'email_sent', 'email_sent_at')
    ordering = ('-timestamp',)
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False

admin.site.register(User, CustomUserAdmin)

# Customize admin site
admin.site.site_header = "Kiharu Bursary Management System"
admin.site.site_title = "Bursary Admin"
admin.site.index_title = "Welcome to Bursary Administration"