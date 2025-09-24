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


from django.contrib import admin
from django.contrib.auth.models import User
from django.db.models import Sum, Count
from django.utils.html import format_html
from django.urls import reverse
from django.shortcuts import redirect
from django.http import HttpResponseRedirect
from django.utils import timezone
import json

from .models import (
    BulkCheque, BulkChequeAllocation, AIAnalysisReport, 
    PredictionModel, DataSnapshot
)

# Custom Admin Filters
class IsCollectedFilter(admin.SimpleListFilter):
    title = 'Collection Status'
    parameter_name = 'is_collected'
    
    def lookups(self, request, model_admin):
        return (
            ('collected', 'Collected'),
            ('pending', 'Pending Collection'),
        )
    
    def queryset(self, request, queryset):
        if self.value() == 'collected':
            return queryset.filter(is_collected=True)
        if self.value() == 'pending':
            return queryset.filter(is_collected=False)

class ReportTypeFilter(admin.SimpleListFilter):
    title = 'Report Type'
    parameter_name = 'report_type'
    
    def lookups(self, request, model_admin):
        return AIAnalysisReport.REPORT_TYPES
    
    def queryset(self, request, queryset):
        if self.value():
            return queryset.filter(report_type=self.value())

class ModelTypeFilter(admin.SimpleListFilter):
    title = 'Model Type'
    parameter_name = 'model_type'
    
    def lookups(self, request, model_admin):
        return PredictionModel.MODEL_TYPES
    
    def queryset(self, request, queryset):
        if self.value():
            return queryset.filter(model_type=self.value())

# Inline Admin Classes
class BulkChequeAllocationInline(admin.TabularInline):
    model = BulkChequeAllocation
    extra = 0
    readonly_fields = ['student_name', 'admission_number', 'amount', 'is_notified']
    fields = ['student_name', 'admission_number', 'amount', 'is_notified', 'notification_sent_date']
    
    def student_name(self, obj):
        return obj.allocation.application.applicant.get_full_name()
    student_name.short_description = 'Student Name'
    
    def admission_number(self, obj):
        return obj.allocation.application.admission_number
    admission_number.short_description = 'Admission No.'
    
    def amount(self, obj):
        return f"KES {obj.allocation.amount_allocated:,.2f}"
    amount.short_description = 'Amount'
    
    def has_add_permission(self, request, obj=None):
        return False
    
    def has_delete_permission(self, request, obj=None):
        return False

# Main Admin Classes
@admin.register(BulkCheque)
class BulkChequeAdmin(admin.ModelAdmin):
    list_display = [
        'cheque_number', 'institution', 'student_count', 
        'total_amount_display', 'cheque_holder_name', 
        'created_date', 'collection_status', 'admin_actions'
    ]
    
    list_filter = [
        IsCollectedFilter, 'institution', 'fiscal_year', 
        'created_date', 'is_collected'
    ]
    
    search_fields = [
        'cheque_number', 'institution__name', 
        'cheque_holder_name', 'cheque_holder_id'
    ]
    
    readonly_fields = [
        'total_amount', 'student_count', 'amount_per_student',
        'created_date', 'allocations_list', 'collection_status_display'
    ]
    
    fieldsets = (
        ('Basic Information', {
            'fields': (
                'cheque_number', 'institution', 'fiscal_year',
                'total_amount', 'student_count', 'amount_per_student'
            )
        }),
        ('Cheque Holder Details', {
            'fields': (
                'cheque_holder_name', 'cheque_holder_position',
                'cheque_holder_id', 'cheque_holder_phone', 
                'cheque_holder_email'
            )
        }),
        ('Status Information', {
            'fields': (
                'is_collected', 'collection_status_display',
                'created_date', 'assigned_date', 'collection_date',
                'created_by', 'assigned_by'
            )
        }),
        ('Allocations', {
            'fields': ('allocations_list',)
        }),
        ('Additional Information', {
            'fields': ('notes',),
            'classes': ('collapse',)
        })
    )
    
    inlines = [BulkChequeAllocationInline]
    
    # FIX: Define actions as a list/tuple, not a method
    actions = ['mark_as_collected', 'mark_as_pending']
    
    def total_amount_display(self, obj):
        return f"KES {obj.total_amount:,.2f}"
    total_amount_display.short_description = 'Total Amount'
    total_amount_display.admin_order_field = 'total_amount'
    
    def collection_status(self, obj):
        if obj.is_collected:
            return format_html(
                '<span class="badge badge-success">Collected</span><br>'
                '<small>{}</small>'.format(
                    obj.collection_date.strftime('%Y-%m-%d %H:%M') if obj.collection_date else ''
                )
            )
        else:
            return format_html('<span class="badge badge-warning">Pending Collection</span>')
    collection_status.short_description = 'Status'
    
    def collection_status_display(self, obj):
        return self.collection_status(obj)
    collection_status_display.short_description = 'Collection Status'
    
    def allocations_list(self, obj):
        allocations = obj.allocations.select_related(
            'allocation__application__applicant'
        )[:10]  # Show first 10 allocations
        
        items = []
        for alloc in allocations:
            student_name = alloc.allocation.application.applicant.get_full_name()
            amount = alloc.allocation.amount_allocated
            items.append(f"• {student_name}: KES {amount:,.2f}")
        
        if obj.allocations.count() > 10:
            items.append(f"... and {obj.allocations.count() - 10} more")
        
        return format_html("<br>".join(items))
    allocations_list.short_description = 'Student Allocations'
    
    # FIX: Renamed from 'actions' to avoid conflict
    def admin_actions(self, obj):
        view_url = reverse('admin:kiharu_system_bulkcheque_change', args=[obj.id])
        notify_url = reverse('send_bulk_notifications')

        
        buttons = [
            f'<a href="{view_url}" class="button">View</a>',
        ]
        
        if not obj.is_collected:
            buttons.append(
                f'<a href="{notify_url}" class="button" style="background-color: #28a745;">Notify</a>'
            )
        
        return format_html(' '.join(buttons))
    admin_actions.short_description = 'Actions'
    admin_actions.allow_tags = True
    
    # Custom admin actions
    def mark_as_collected(self, request, queryset):
        updated = queryset.update(
            is_collected=True, 
            collection_date=timezone.now(),
            assigned_by=request.user
        )
        self.message_user(request, f"{updated} bulk cheques marked as collected.")
    mark_as_collected.short_description = "Mark selected as collected"
    
    def mark_as_pending(self, request, queryset):
        updated = queryset.update(is_collected=False, collection_date=None)
        self.message_user(request, f"{updated} bulk cheques marked as pending collection.")
    mark_as_pending.short_description = "Mark selected as pending collection"
    
    def save_model(self, request, obj, form, change):
        if not obj.pk:  # New object
            obj.created_by = request.user
        obj.assigned_by = request.user
        super().save_model(request, obj, form, change)
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related(
            'institution', 'fiscal_year', 'created_by', 'assigned_by'
        ).prefetch_related('allocations')

@admin.register(BulkChequeAllocation)
class BulkChequeAllocationAdmin(admin.ModelAdmin):
    list_display = [
        'bulk_cheque', 'student_name', 'admission_number', 
        'amount_allocated', 'institution', 'is_notified', 
        'notification_date'
    ]
    
    list_filter = ['is_notified', 'bulk_cheque__institution', 'notification_sent_date']
    
    search_fields = [
        'bulk_cheque__cheque_number',
        'allocation__application__applicant__first_name',
        'allocation__application__applicant__last_name',
        'allocation__application__admission_number'
    ]
    
    readonly_fields = [
        'student_info', 'allocation_details', 'bulk_cheque_info'
    ]
    
    fieldsets = (
        ('Bulk Cheque Information', {
            'fields': ('bulk_cheque_info',)
        }),
        ('Student Information', {
            'fields': ('student_info',)
        }),
        ('Allocation Details', {
            'fields': ('allocation_details',)
        }),
        ('Notification Status', {
            'fields': ('is_notified', 'notification_sent_date')
        })
    )
    
    # FIX: No actions defined for this model
    # actions = []  # Optional: define if you need custom actions
    
    def student_name(self, obj):
        return obj.allocation.application.applicant.get_full_name()
    student_name.short_description = 'Student Name'
    student_name.admin_order_field = 'allocation__application__applicant__first_name'
    
    def admission_number(self, obj):
        return obj.allocation.application.admission_number
    admission_number.short_description = 'Admission No.'
    
    def amount_allocated(self, obj):
        return f"KES {obj.allocation.amount_allocated:,.2f}"
    amount_allocated.short_description = 'Amount'
    amount_allocated.admin_order_field = 'allocation__amount_allocated'
    
    def institution(self, obj):
        return obj.bulk_cheque.institution
    institution.short_description = 'Institution'
    institution.admin_order_field = 'bulk_cheque__institution__name'
    
    def notification_date(self, obj):
        if obj.notification_sent_date:
            return obj.notification_sent_date.strftime('%Y-%m-%d %H:%M')
        return '-'
    notification_date.short_description = 'Notified On'
    
    def student_info(self, obj):
        app = obj.allocation.application
        return format_html(
            "<strong>Name:</strong> {}<br>"
            "<strong>Admission No:</strong> {}<br>"
            "<strong>Course:</strong> {}<br>"
            "<strong>Year:</strong> {}<br>"
            "<strong>Contact:</strong> {} | {}<br>".format(
                app.applicant.get_full_name(),
                app.admission_number,
                app.course,
                app.year_of_study,
                app.applicant.email,
                app.applicant.phone_number if hasattr(app.applicant, 'phone_number') else 'N/A'
            )
        )
    student_info.short_description = 'Student Details'
    
    def allocation_details(self, obj):
        alloc = obj.allocation
        return format_html(
            "<strong>Amount Allocated:</strong> KES {:,.2f}<br>"
            "<strong>Academic Year:</strong> {}<br>"
            "<strong>Allocation Date:</strong> {}<br>".format(
                alloc.amount_allocated,
                alloc.fiscal_year,
                alloc.allocation_date.strftime('%Y-%m-%d') if alloc.allocation_date else 'N/A'
            )
        )
    allocation_details.short_description = 'Allocation Information'
    
    def bulk_cheque_info(self, obj):
        return format_html(
            "<strong>Cheque Number:</strong> {}<br>"
            "<strong>Institution:</strong> {}<br>"
            "<strong>Total Amount:</strong> KES {:,.2f}<br>"
            "<strong>Student Count:</strong> {}".format(
                obj.bulk_cheque.cheque_number,
                obj.bulk_cheque.institution.name,
                obj.bulk_cheque.total_amount,
                obj.bulk_cheque.student_count
            )
        )
    bulk_cheque_info.short_description = 'Bulk Cheque Details'
    
    def has_add_permission(self, request):
        return False
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related(
            'bulk_cheque__institution',
            'allocation__application__applicant',
            
        )

@admin.register(AIAnalysisReport)
class AIAnalysisReportAdmin(admin.ModelAdmin):
    list_display = [
        'title', 'report_type_display', 'fiscal_year', 
        'generated_date', 'generated_by', 'accuracy_score_display',
        'confidence_display', 'admin_actions'
    ]
    
    list_filter = [ReportTypeFilter, 'fiscal_year', 'generated_date', 'is_archived']
    
    search_fields = ['title', 'report_type', 'fiscal_year__name']
    
    readonly_fields = [
        'generated_date', 'analysis_data_preview', 
        'predictions_preview', 'recommendations_preview'
    ]
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('title', 'report_type', 'fiscal_year', 'is_archived')
        }),
        ('Analysis Data', {
            'fields': ('analysis_data_preview', 'analysis_data')
        }),
        ('Predictions & Recommendations', {
            'fields': ('predictions_preview', 'predictions', 'recommendations_preview', 'recommendations'),
            'classes': ('collapse',)
        }),
        ('Performance Metrics', {
            'fields': ('accuracy_score', 'confidence_level')
        }),
        ('File Attachment', {
            'fields': ('report_file',)
        }),
        ('Metadata', {
            'fields': ('generated_date', 'generated_by'),
            'classes': ('collapse',)
        })
    )
    
    # FIX: Define actions as list/tuple
    actions = ['archive_reports', 'unarchive_reports']
    
    def report_type_display(self, obj):
        return obj.get_report_type_display()
    report_type_display.short_description = 'Report Type'
    
    def accuracy_score_display(self, obj):
        if obj.accuracy_score:
            return f"{float(obj.accuracy_score) * 100:.1f}%"
        return '-'
    accuracy_score_display.short_description = 'Accuracy'
    
    def confidence_display(self, obj):
        if obj.confidence_level:
            return f"{obj.confidence_level}%"
        return '-'
    confidence_display.short_description = 'Confidence'
    
    def analysis_data_preview(self, obj):
        if obj.analysis_data:
            preview = json.dumps(obj.analysis_data, indent=2)[:500] + "..." if len(json.dumps(obj.analysis_data)) > 500 else json.dumps(obj.analysis_data, indent=2)
            return format_html('<pre style="font-size: 10px;">{}</pre>', preview)
        return '-'
    analysis_data_preview.short_description = 'Analysis Data (Preview)'
    
    def predictions_preview(self, obj):
        if obj.predictions:
            preview = json.dumps(obj.predictions, indent=2)[:500] + "..." if len(json.dumps(obj.predictions)) > 500 else json.dumps(obj.predictions, indent=2)
            return format_html('<pre style="font-size: 10px;">{}</pre>', preview)
        return '-'
    predictions_preview.short_description = 'Predictions (Preview)'
    
    def recommendations_preview(self, obj):
        if obj.recommendations:
            preview = json.dumps(obj.recommendations, indent=2)[:500] + "..." if len(json.dumps(obj.recommendations)) > 500 else json.dumps(obj.recommendations, indent=2)
            return format_html('<pre style="font-size: 10px;">{}</pre>', preview)
        return '-'
    recommendations_preview.short_description = 'Recommendations (Preview)'
    
    # FIX: Renamed from 'actions' to avoid conflict
    def admin_actions(self, obj):
        view_url = reverse('admin:bursary_aianalysisreport_change', args=[obj.id])
        download_url = obj.report_file.url if obj.report_file else '#'
        
        buttons = [f'<a href="{view_url}" class="button">View</a>']
        
        if obj.report_file:
            buttons.append(f'<a href="{download_url}" class="button" style="background-color: #17a2b8;">Download</a>')
        
        return format_html(' '.join(buttons))
    admin_actions.short_description = 'Actions'
    
    # Custom admin actions
    def archive_reports(self, request, queryset):
        updated = queryset.update(is_archived=True)
        self.message_user(request, f"{updated} reports archived.")
    archive_reports.short_description = "Archive selected reports"
    
    def unarchive_reports(self, request, queryset):
        updated = queryset.update(is_archived=False)
        self.message_user(request, f"{updated} reports unarchived.")
    unarchive_reports.short_description = "Unarchive selected reports"
    
    def save_model(self, request, obj, form, change):
        if not obj.pk:  # New object
            obj.generated_by = request.user
        super().save_model(request, obj, form, change)

@admin.register(PredictionModel)
class PredictionModelAdmin(admin.ModelAdmin):
    list_display = [
        'name', 'model_type_display', 'version', 'is_active',
        'accuracy_display', 'training_date', 'last_retrained',
        'training_data_size', 'admin_actions'
    ]
    
    list_filter = [ModelTypeFilter, 'is_active', 'training_date']
    
    search_fields = ['name', 'model_type', 'version']
    
    readonly_fields = [
        'training_date', 'feature_importance_preview',
        'model_parameters_preview', 'performance_metrics'
    ]
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'model_type', 'version', 'is_active')
        }),
        ('Model Parameters', {
            'fields': ('model_parameters_preview', 'model_parameters')
        }),
        ('Feature Importance', {
            'fields': ('feature_importance_preview', 'feature_importance'),
            'classes': ('collapse',)
        }),
        ('Performance Metrics', {
            'fields': ('performance_metrics', 'accuracy', 'precision', 'recall', 'f1_score')
        }),
        ('Training Information', {
            'fields': ('training_data_size', 'training_date', 'last_retrained', 'created_by'),
            'classes': ('collapse',)
        })
    )
    
    # FIX: Define actions as list/tuple
    actions = ['activate_models', 'deactivate_models']
    
    def model_type_display(self, obj):
        return obj.get_model_type_display()
    model_type_display.short_description = 'Model Type'
    
    def accuracy_display(self, obj):
        if obj.accuracy:
            return f"{float(obj.accuracy) * 100:.1f}%"
        return '-'
    accuracy_display.short_description = 'Accuracy'
    
    def feature_importance_preview(self, obj):
        if obj.feature_importance:
            preview = json.dumps(obj.feature_importance, indent=2)[:500] + "..." if len(json.dumps(obj.feature_importance)) > 500 else json.dumps(obj.feature_importance, indent=2)
            return format_html('<pre style="font-size: 10px;">{}</pre>', preview)
        return '-'
    feature_importance_preview.short_description = 'Feature Importance (Preview)'
    
    def model_parameters_preview(self, obj):
        if obj.model_parameters:
            preview = json.dumps(obj.model_parameters, indent=2)[:500] + "..." if len(json.dumps(obj.model_parameters)) > 500 else json.dumps(obj.model_parameters, indent=2)
            return format_html('<pre style="font-size: 10px;">{}</pre>', preview)
        return '-'
    model_parameters_preview.short_description = 'Model Parameters (Preview)'
    
    def performance_metrics(self, obj):
        metrics = []
        if obj.accuracy:
            metrics.append(f"Accuracy: {float(obj.accuracy) * 100:.1f}%")
        if obj.precision:
            metrics.append(f"Precision: {float(obj.precision) * 100:.1f}%")
        if obj.recall:
            metrics.append(f"Recall: {float(obj.recall) * 100:.1f}%")
        if obj.f1_score:
            metrics.append(f"F1 Score: {float(obj.f1_score) * 100:.1f}%")
        
        return format_html("<br>".join(metrics)) if metrics else '-'
    performance_metrics.short_description = 'Current Metrics'
    
    # FIX: Renamed from 'actions' to avoid conflict
    def admin_actions(self, obj):
        view_url = reverse('admin:bursary_predictionmodel_change', args=[obj.id])
        return format_html(f'<a href="{view_url}" class="button">View Details</a>')
    admin_actions.short_description = 'Actions'
    
    # Custom admin actions
    def activate_models(self, request, queryset):
        updated = queryset.update(is_active=True, last_retrained=timezone.now())
        self.message_user(request, f"{updated} models activated.")
    activate_models.short_description = "Activate selected models"
    
    def deactivate_models(self, request, queryset):
        updated = queryset.update(is_active=False)
        self.message_user(request, f"{updated} models deactivated.")
    deactivate_models.short_description = "Deactivate selected models"
    
    def save_model(self, request, obj, form, change):
        if not obj.pk:  # New object
            obj.created_by = request.user
        super().save_model(request, obj, form, change)

@admin.register(DataSnapshot)
class DataSnapshotAdmin(admin.ModelAdmin):
    list_display = [
        'snapshot_date', 'fiscal_year', 'total_applications',
        'total_allocated_display', 'approval_rate_display',
        'created_at', 'admin_actions'
    ]
    
    list_filter = ['fiscal_year', 'snapshot_date', 'created_at']
    
    search_fields = ['fiscal_year__name', 'snapshot_date']
    
    readonly_fields = [
        'created_at', 'distributions_preview', 'financial_summary'
    ]
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('snapshot_date', 'fiscal_year', 'created_at')
        }),
        ('Application Statistics', {
            'fields': (
                'total_applications', 'approved_applications',
                'rejected_applications', 'pending_applications',
                'approval_rate'
            )
        }),
        ('Financial Data', {
            'fields': (
                'financial_summary', 'total_requested', 'total_allocated',
                'total_disbursed', 'average_amount_requested',
                'average_amount_allocated'
            )
        }),
        ('Distributions', {
            'fields': ('distributions_preview', 'gender_distribution', 
                      'ward_distribution', 'institution_distribution',
                      'category_distribution'),
            'classes': ('collapse',)
        })
    )
    
    # FIX: Define actions as list/tuple (optional - can be empty)
    actions = []  # No custom actions needed for this model
    
    def total_allocated_display(self, obj):
        return f"KES {obj.total_allocated:,.2f}"
    total_allocated_display.short_description = 'Total Allocated'
    
    def approval_rate_display(self, obj):
        return f"{obj.approval_rate}%"
    approval_rate_display.short_description = 'Approval Rate'
    
    def distributions_preview(self, obj):
        distributions = []
        if obj.gender_distribution:
            distributions.append(f"Gender: {json.dumps(obj.gender_distribution)}")
        if obj.ward_distribution:
            distributions.append(f"Wards: {len(obj.ward_distribution)} wards")
        if obj.institution_distribution:
            distributions.append(f"Institutions: {len(obj.institution_distribution)} institutions")
        if obj.category_distribution:
            distributions.append(f"Categories: {json.dumps(obj.category_distribution)}")
        
        return format_html("<br>".join(distributions))
    distributions_preview.short_description = 'Distributions Summary'
    
    def financial_summary(self, obj):
        return format_html(
            "<strong>Total Requested:</strong> KES {:,.2f}<br>"
            "<strong>Total Allocated:</strong> KES {:,.2f}<br>"
            "<strong>Total Disbursed:</strong> KES {:,.2f}<br>"
            "<strong>Allocation Rate:</strong> {:.1f}%".format(
                obj.total_requested,
                obj.total_allocated,
                obj.total_disbursed,
                (obj.total_allocated / obj.total_requested * 100) if obj.total_requested > 0 else 0
            )
        )
    financial_summary.short_description = 'Financial Overview'
    
    # FIX: Renamed from 'actions' to avoid conflict
    def admin_actions(self, obj):
        view_url = reverse('admin:bursary_datasnapshot_change', args=[obj.id])
        return format_html(f'<a href="{view_url}" class="button">View Details</a>')
    admin_actions.short_description = 'Actions'


admin.site.register(User, CustomUserAdmin)

# Customize admin site
admin.site.site_header = "Kiharu Bursary Management System"
admin.site.site_title = "Bursary Admin"
admin.site.index_title = "Welcome to Bursary Administration"