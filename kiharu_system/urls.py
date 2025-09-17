from django.urls import path
from . import views

urlpatterns = [
    # Authentication
    path('', views.login_view, name='login_view'),
    path('logout/', views.login_view, name='login_view'),
    
    # Dashboards
    path('dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('reviewer-dashboard/', views.reviewer_dashboard, name='reviewer_dashboard'),
    path('finance-dashboard/', views.finance_dashboard, name='finance_dashboard'),
    
    # Applications
    path('applications/', views.application_list, name='application_list'),
    path('applications/<int:application_id>/', views.application_detail, name='application_detail'),
    path('applications/<int:application_id>/review/', views.application_review, name='application_review'),
    
    # Applicants
    path('applicants/', views.applicant_list, name='applicant_list'),
    path('applicants/<int:applicant_id>/', views.applicant_detail, name='applicant_detail'),
    
    # Budget & Allocation
    path('fiscal-years/', views.fiscal_year_list, name='fiscal_year_list'),
    path('fiscal-years/create/', views.fiscal_year_create, name='fiscal_year_create'),
    path('bursary-categories/', views.bursary_category_list, name='bursary_category_list'),
    path('allocations/', views.allocation_list, name='allocation_list'),
    path('allocations/<int:allocation_id>/disburse/', views.disbursement_create, name='disbursement_create'),
    
    # Institutions
    path('institutions/', views.institution_list, name='institution_list'),
    path('institutions/create/', views.institution_create, name='institution_create'),
    
    # User Management
    path('users/', views.user_list, name='user_list'),
    path('users/create/', views.user_create, name='user_create'),
    
    # Settings
    path('settings/', views.system_settings, name='system_settings'),
    path('announcements/', views.announcement_list, name='announcement_list'),
    path('announcements/create/', views.announcement_create, name='announcement_create'),
    path('faq/', views.faq_list, name='faq_list'),
    
    # Reports
    path('reports/applications/', views.application_reports, name='application_reports'),
    path('reports/financial/', views.financial_reports, name='financial_reports'),
    
    # Audit
    path('audit-logs/', views.audit_log_list, name='audit_log_list'),
    
    # Ward Management
    path('wards/', views.ward_list, name='ward_list'),
    path('wards/<int:ward_id>/locations/', views.location_list, name='location_list'),
]