from django.urls import path
from . import views

urlpatterns = [
    # Authentication
    path('', views.login_view, name='login_view'),
    path('logout/', views.logout_view, name='logout_view'),
    
    # Dashboards
    path('dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('reviewer-dashboard/', views.reviewer_dashboard, name='reviewer_dashboard'),
    path('finance-dashboard/', views.finance_dashboard, name='finance_dashboard'),
    
    # Applications
    path('applications/', views.application_list, name='application_list'),
    path('applications/create/', views.CreateApplicationView.as_view(), name='create_application'), #by admin
    path('applications/<int:application_id>/', views.application_detail, name='application_detail'),
    path('applications/<int:application_id>/review/', views.application_review, name='application_review'),

    # PDF document serving URLs
    path('application/<int:application_id>/document/<int:document_id>/serve/',  views.serve_pdf_document,  name='serve_pdf_document'),
    path('application/<int:application_id>/document/<int:document_id>/viewer/',  views.pdf_viewer, name='pdf_viewer'),
    path('application/<int:application_id>/document/<int:document_id>/proxy/',  views.document_proxy,  name='document_proxy'),
    
    # Applicants
    path('applicants/', views.applicant_list, name='applicant_list'),
    path('applicants/<int:applicant_id>/', views.applicant_detail, name='applicant_detail'),

    # Fiscal Year URLs
    path('admin-fiscal-years/', views.fiscal_year_list, name='fiscal_year_list'),
    path('admin-fiscal-years/create/', views.fiscal_year_create, name='fiscal_year_create'),
    path('admin-fiscal-years/<int:pk>/', views.fiscal_year_detail, name='fiscal_year_detail'),
    path('admin-fiscal-years/<int:pk>/edit/', views.fiscal_year_update, name='fiscal_year_update'),
    path('admin-fiscal-years/<int:pk>/delete/', views.fiscal_year_delete, name='fiscal_year_delete'),
    path('admin-fiscal-years/<int:pk>/analytics/', views.fiscal_year_analytics, name='fiscal_year_analytics'),
    path('admin-fiscal-years/<int:pk>/toggle-active/', views.fiscal_year_toggle_active, name='fiscal_year_toggle_active'),
    
    # Bursary Category URLs
    path('admin-bursary-categories/', views.bursary_category_list, name='bursary_category_list'),
    path('admin-bursary-categories/create/', views.bursary_category_create, name='bursary_category_create'),
    path('admin-bursary-categories/<int:pk>/', views.bursary_category_detail, name='bursary_category_detail'),
    
    # Budget & Allocation

    path('allocations/', views.allocation_list, name='allocation_list'),
    path('allocations/<int:allocation_id>/disburse/', views.disbursement_create, name='disbursement_create'),
    
    # Institutions
    path('institutions/', views.institution_list, name='institution_list'),
    # AJAX endpoints
    path('institutions/create/', views.institution_create, name='institution_create'),
    path('institutions/<int:pk>/detail/', views.institution_detail, name='institution_detail'),
    path('institutions/<int:pk>/update/', views.institution_update, name='institution_update'),
    path('institutions/<int:pk>/delete/', views.institution_delete, name='institution_delete'),
    path('institutions/search/', views.institution_search, name='institution_search'),

    
    # User Management
  
    path('users/', views.UserManagementView.as_view(), name='user_management'),
    path('admin-users/create/', views.user_create_ajax, name='user_create_ajax'),
    path('admin-users/<int:user_id>/', views.user_detail_ajax, name='user_detail_ajax'),
    path('admin-users/<int:user_id>/update/', views.user_update_ajax, name='user_update_ajax'),
    path('users/<int:user_id>/delete/', views.user_delete_ajax, name='user_delete_ajax'),
    path('users/<int:user_id>/reset-password/', views.user_reset_password_ajax, name='user_reset_password_ajax'),
    
    # Settings
    path('settings/', views.system_settings, name='system_settings'),
    path('announcements/', views.announcement_list, name='announcement_list'),
    path('announcements/create/', views.announcement_create, name='announcement_create'),
    path('faq/', views.faq_list, name='faq_list'),
    
    # Reports graphs 
    path('reports/applications/', views.application_reports, name='application_reports'),
    path('reports/financial/', views.financial_reports, name='financial_reports'),
    path('reports/wards/', views.ward_reports, name='ward_reports'),
    path('reports/institutions/', views.institution_reports, name='institution_reports'),
    
    # Audit
    path('audit-logs/', views.audit_log_list, name='audit_log_list'),
    
    # Ward Management
    path('wards/', views.ward_list, name='ward_list'),
    path('wards/<int:ward_id>/locations/', views.location_list, name='location_list'),

    # Students Dashboard
    path('student/dashboard/', views.student_dashboard, name='student_dashboard'),
    
    # Profile Management
    path('student/profile/create/', views.student_profile_create, name='student_profile_create'),
    path('student/profile/view/', views.student_profile_view, name='student_profile_view'),
    path('student/profile/edit/', views.student_profile_create, name='student_profile_edit'),
    
    # Guardian and Sibling Management
    path('student/guardian/add/', views.student_guardian_create, name='guardian_create'),
    path('student/sibling/add/', views.student_sibling_create, name='sibling_create'),
    
    # Application Management
    path('student/applications/', views.student_application_list, name='student_application_list'),
    path('student/application/new/', views.student_application_create, name='student_application_create'),
    path('get-category-max-amount/', views.get_category_max_amount, name='get_category_max_amount'),
    path('student/application/<int:pk>/', views.student_application_detail, name='student_application_detail'),
    path('student/application/<int:pk>/edit/', views.student_application_edit, name='student_application_edit'),
    path('student/application/<int:pk>/documents/', views.student_application_documents, name='student_application_documents'),
    path('student/application/<int:pk>/submit/', views.student_application_submit, name='student_application_submit'),
    path('application/<int:application_id>/document/<int:document_id>/preview/', views.document_preview, name='document_preview'),
    
    # Document Management
    path('student/document/<int:pk>/delete/', views.student_document_delete, name='student_document_delete'),
    
    # Notifications
    path('student/notifications/', views.notifications_list, name='notifications_list'),
    
    # Information Pages
    path('student/faqs/', views.faqs_view, name='faqs_view'),
    path('student/announcements/', views.announcements_view, name='announcements_view'),
    
    # AJAX endpoints
    path('ajax/locations/', views.get_locations, name='get_locations'),
    path('ajax/sublocations/', views.get_sublocations, name='get_sublocations'),
    path('ajax/villages/', views.get_villages, name='get_villages'),
    path('ajax/application-status/<int:pk>/', views.application_status_check, name='application_status_check'),

    # Admin Profile Settings
    path('admin-profile/', views.admin_profile_settings, name='admin_profile_settings'),
    
    # Help & Support
    path('admin-help/', views.admin_help_support, name='admin_help_support'),
    path('admin-faq/<int:faq_id>/toggle/', views.toggle_faq_status, name='toggle_faq_status'),
    
    # Preferences
    path('admin-preferences/', views.admin_preferences, name='admin_preferences'),
    path('admin-settings/<int:setting_id>/delete/', views.delete_system_setting, name='delete_system_setting'),
    
    # Communication
    path('admin-communication/', views.admin_communication, name='admin_communication'),
    path('admin-announcements/<int:announcement_id>/toggle/', views.toggle_announcement_status, name='toggle_announcement_status'),
    
    # Security & Audit
    path('admin-security/', views.admin_security_audit, name='admin_security_audit'),
    path('admin-audit-log/<int:log_id>/details/', views.get_audit_log_details, name='get_audit_log_details'),
]