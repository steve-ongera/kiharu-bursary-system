from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.http import JsonResponse
from django.db.models import Q, Sum, Count
from django.core.paginator import Paginator
from django.utils import timezone
from django.forms.models import modelform_factory
from .models import *
from .forms import *
import json

# Authentication Views
def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        
        if user is not None and user.user_type in ['admin', 'reviewer', 'finance']:
            login(request, user)
            # Redirect based on user type
            if user.user_type == 'admin':
                return redirect('admin_dashboard')
            elif user.user_type == 'reviewer':
                return redirect('reviewer_dashboard')
            elif user.user_type == 'finance':
                return redirect('finance_dashboard')
        else:
            messages.error(request, 'Invalid credentials or insufficient permissions')
    
    return render(request, 'auth/login.html')

@login_required
def logout_view(request):
    logout(request)
    return redirect('login_view')

# Helper function to check user type
def is_admin(user):
    return user.user_type == 'admin'

def is_reviewer(user):
    return user.user_type in ['admin', 'reviewer']

def is_finance(user):
    return user.user_type in ['admin', 'finance']

# Dashboard Views
@login_required
@user_passes_test(is_admin)
def admin_dashboard(request):
    # Statistics
    total_applications = Application.objects.count()
    pending_applications = Application.objects.filter(status='submitted').count()
    approved_applications = Application.objects.filter(status='approved').count()
    total_allocated = Allocation.objects.aggregate(Sum('amount_allocated'))['amount_allocated__sum'] or 0
    
    # Recent applications
    recent_applications = Application.objects.order_by('-date_submitted')[:10]
    
    # Applications by ward
    ward_stats = Application.objects.values('applicant__ward__name').annotate(count=Count('id'))
    
    # Applications by status
    status_stats = Application.objects.values('status').annotate(count=Count('id'))
    
    context = {
        'total_applications': total_applications,
        'pending_applications': pending_applications,
        'approved_applications': approved_applications,
        'total_allocated': total_allocated,
        'recent_applications': recent_applications,
        'ward_stats': ward_stats,
        'status_stats': status_stats,
    }
    return render(request, 'admin/dashboard.html', context)

@login_required
@user_passes_test(is_reviewer)
def reviewer_dashboard(request):
    # Applications for review
    pending_review = Application.objects.filter(status='submitted')
    under_review = Application.objects.filter(status='under_review')
    my_reviews = Review.objects.filter(reviewer=request.user).count()
    
    context = {
        'pending_review': pending_review,
        'under_review': under_review,
        'my_reviews': my_reviews,
    }
    return render(request, 'admin/reviewer_dashboard.html', context)

@login_required
@user_passes_test(is_finance)
def finance_dashboard(request):
    # Financial statistics
    approved_allocations = Allocation.objects.filter(is_disbursed=False)
    total_pending_disbursement = approved_allocations.aggregate(Sum('amount_allocated'))['amount_allocated__sum'] or 0
    disbursed_today = Allocation.objects.filter(disbursement_date=timezone.now().date()).count()
    
    context = {
        'approved_allocations': approved_allocations,
        'total_pending_disbursement': total_pending_disbursement,
        'disbursed_today': disbursed_today,
    }
    return render(request, 'admin/finance_dashboard.html', context)

# Application Views
@login_required
@user_passes_test(is_reviewer)
def application_list(request):
    applications = Application.objects.all().select_related('applicant__user', 'institution', 'bursary_category')
    
    # Filtering
    status = request.GET.get('status')
    ward = request.GET.get('ward')
    institution_type = request.GET.get('institution_type')
    
    if status:
        applications = applications.filter(status=status)
    if ward:
        applications = applications.filter(applicant__ward__id=ward)
    if institution_type:
        applications = applications.filter(bursary_category__category_type=institution_type)
    
    paginator = Paginator(applications, 25)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Filter options
    wards = Ward.objects.all()
    
    context = {
        'page_obj': page_obj,
        'wards': wards,
        'current_status': status,
        'current_ward': ward,
        'current_institution_type': institution_type,
    }
    return render(request, 'admin/application_list.html', context)

@login_required
@user_passes_test(is_reviewer)
def application_detail(request, application_id):
    application = get_object_or_404(Application, id=application_id)
    reviews = Review.objects.filter(application=application).order_by('-review_date')
    documents = Document.objects.filter(application=application)
    
    context = {
        'application': application,
        'reviews': reviews,
        'documents': documents,
    }
    return render(request, 'admin/application_detail.html', context)

@login_required
@user_passes_test(is_reviewer)
def application_review(request, application_id):
    application = get_object_or_404(Application, id=application_id)
    
    if request.method == 'POST':
        comments = request.POST['comments']
        recommendation = request.POST['recommendation']
        recommended_amount = request.POST.get('recommended_amount')
        
        review = Review.objects.create(
            application=application,
            reviewer=request.user,
            comments=comments,
            recommendation=recommendation,
            recommended_amount=recommended_amount if recommended_amount else None
        )
        
        # Update application status
        if recommendation == 'approve':
            application.status = 'approved'
            # Create allocation
            if recommended_amount:
                Allocation.objects.create(
                    application=application,
                    amount_allocated=recommended_amount,
                    approved_by=request.user
                )
        elif recommendation == 'reject':
            application.status = 'rejected'
        else:
            application.status = 'under_review'
        
        application.save()
        messages.success(request, 'Review submitted successfully')
        return redirect('application_detail', application_id=application.id)
    
    context = {'application': application}
    return render(request, 'admin/application_review.html', context)

# Applicant Views
@login_required
@user_passes_test(is_admin)
def applicant_list(request):
    applicants = Applicant.objects.all().select_related('user', 'ward')
    
    # Filtering
    ward = request.GET.get('ward')
    gender = request.GET.get('gender')
    special_needs = request.GET.get('special_needs')
    
    if ward:
        applicants = applicants.filter(ward__id=ward)
    if gender:
        applicants = applicants.filter(gender=gender)
    if special_needs == 'true':
        applicants = applicants.filter(special_needs=True)
    
    paginator = Paginator(applicants, 25)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    wards = Ward.objects.all()
    
    context = {
        'page_obj': page_obj,
        'wards': wards,
        'current_ward': ward,
        'current_gender': gender,
        'current_special_needs': special_needs,
    }
    return render(request, 'admin/applicant_list.html', context)

@login_required
@user_passes_test(is_admin)
def applicant_detail(request, applicant_id):
    applicant = get_object_or_404(Applicant, id=applicant_id)
    guardians = Guardian.objects.filter(applicant=applicant)
    siblings = SiblingInformation.objects.filter(applicant=applicant)
    applications = Application.objects.filter(applicant=applicant).order_by('-date_submitted')
    
    context = {
        'applicant': applicant,
        'guardians': guardians,
        'siblings': siblings,
        'applications': applications,
    }
    return render(request, 'admin/applicant_detail.html', context)

# Budget and Allocation Views
@login_required
@user_passes_test(is_admin)
def fiscal_year_list(request):
    fiscal_years = FiscalYear.objects.all().order_by('-start_date')
    
    context = {'fiscal_years': fiscal_years}
    return render(request, 'admin/fiscal_year_list.html', context)

@login_required
@user_passes_test(is_admin)
def fiscal_year_create(request):
    if request.method == 'POST':
        name = request.POST['name']
        start_date = request.POST['start_date']
        end_date = request.POST['end_date']
        total_allocation = request.POST['total_allocation']
        is_active = 'is_active' in request.POST
        
        # Deactivate other fiscal years if this one is active
        if is_active:
            FiscalYear.objects.all().update(is_active=False)
        
        fiscal_year = FiscalYear.objects.create(
            name=name,
            start_date=start_date,
            end_date=end_date,
            total_allocation=total_allocation,
            is_active=is_active
        )
        
        messages.success(request, 'Fiscal year created successfully')
        return redirect('fiscal_year_list')
    
    return render(request, 'admin/fiscal_year_create.html')

@login_required
@user_passes_test(is_admin)
def bursary_category_list(request):
    categories = BursaryCategory.objects.all().select_related('fiscal_year')
    
    context = {'categories': categories}
    return render(request, 'admin/bursary_category_list.html', context)

@login_required
@user_passes_test(is_admin)
def allocation_list(request):
    allocations = Allocation.objects.all().select_related('application__applicant__user', 'approved_by')
    
    # Filtering
    disbursed = request.GET.get('disbursed')
    if disbursed == 'true':
        allocations = allocations.filter(is_disbursed=True)
    elif disbursed == 'false':
        allocations = allocations.filter(is_disbursed=False)
    
    paginator = Paginator(allocations, 25)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'current_disbursed': disbursed,
    }
    return render(request, 'admin/allocation_list.html', context)

@login_required
@user_passes_test(is_finance)
def disbursement_create(request, allocation_id):
    allocation = get_object_or_404(Allocation, id=allocation_id)
    
    if request.method == 'POST':
        cheque_number = request.POST['cheque_number']
        remarks = request.POST.get('remarks', '')
        
        allocation.cheque_number = cheque_number
        allocation.is_disbursed = True
        allocation.disbursement_date = timezone.now().date()
        allocation.disbursed_by = request.user
        allocation.remarks = remarks
        allocation.save()
        
        # Update application status
        allocation.application.status = 'disbursed'
        allocation.application.save()
        
        messages.success(request, 'Disbursement recorded successfully')
        return redirect('allocation_list')
    
    context = {'allocation': allocation}
    return render(request, 'admin/disbursement_create.html', context)

# Institution Views
@login_required
@user_passes_test(is_admin)
def institution_list(request):
    institutions = Institution.objects.all()
    
    # Filtering
    institution_type = request.GET.get('institution_type')
    county = request.GET.get('county')
    
    if institution_type:
        institutions = institutions.filter(institution_type=institution_type)
    if county:
        institutions = institutions.filter(county__icontains=county)
    
    paginator = Paginator(institutions, 25)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'current_type': institution_type,
        'current_county': county,
    }
    return render(request, 'admin/institution_list.html', context)

@login_required
@user_passes_test(is_admin)
def institution_create(request):
    if request.method == 'POST':
        name = request.POST['name']
        institution_type = request.POST['institution_type']
        county = request.POST['county']
        postal_address = request.POST.get('postal_address', '')
        phone_number = request.POST.get('phone_number', '')
        email = request.POST.get('email', '')
        
        Institution.objects.create(
            name=name,
            institution_type=institution_type,
            county=county,
            postal_address=postal_address,
            phone_number=phone_number,
            email=email
        )
        
        messages.success(request, 'Institution created successfully')
        return redirect('institution_list')
    
    return render(request, 'admin/institution_create.html')

# User Management Views
@login_required
@user_passes_test(is_admin)
def user_list(request):
    users = User.objects.all().exclude(user_type='applicant')
    
    # Filtering
    user_type = request.GET.get('user_type')
    if user_type:
        users = users.filter(user_type=user_type)
    
    paginator = Paginator(users, 25)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'current_user_type': user_type,
    }
    return render(request, 'admin/user_list.html', context)

@login_required
@user_passes_test(is_admin)
def user_create(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        user_type = request.POST['user_type']
        password = request.POST['password']
        
        user = User.objects.create_user(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            user_type=user_type,
            password=password
        )
        
        messages.success(request, 'User created successfully')
        return redirect('user_list')
    
    return render(request, 'admin/user_create.html')

# Settings Views
@login_required
@user_passes_test(is_admin)
def system_settings(request):
    settings = SystemSettings.objects.all()
    
    context = {'settings': settings}
    return render(request, 'admin/system_settings.html', context)

@login_required
@user_passes_test(is_admin)
def announcement_list(request):
    announcements = Announcement.objects.all().order_by('-published_date')
    
    context = {'announcements': announcements}
    return render(request, 'admin/announcement_list.html', context)

@login_required
@user_passes_test(is_admin)
def announcement_create(request):
    if request.method == 'POST':
        title = request.POST['title']
        content = request.POST['content']
        published_date = request.POST['published_date']
        expiry_date = request.POST['expiry_date']
        is_active = 'is_active' in request.POST
        
        Announcement.objects.create(
            title=title,
            content=content,
            published_date=published_date,
            expiry_date=expiry_date,
            is_active=is_active,
            created_by=request.user
        )
        
        messages.success(request, 'Announcement created successfully')
        return redirect('announcement_list')
    
    return render(request, 'admin/announcement_create.html')

@login_required
@user_passes_test(is_admin)
def faq_list(request):
    faqs = FAQ.objects.all().order_by('category', 'order')
    
    context = {'faqs': faqs}
    return render(request, 'admin/faq_list.html', context)

# Audit Log Views
@login_required
@user_passes_test(is_admin)
def audit_log_list(request):
    logs = AuditLog.objects.all().select_related('user').order_by('-timestamp')
    
    paginator = Paginator(logs, 50)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {'page_obj': page_obj}
    return render(request, 'admin/audit_log_list.html', context)

# Report Views
@login_required
@user_passes_test(is_admin)
def application_reports(request):
    # Various application statistics
    total_applications = Application.objects.count()
    applications_by_status = Application.objects.values('status').annotate(count=Count('id'))
    applications_by_ward = Application.objects.values('applicant__ward__name').annotate(count=Count('id'))
    applications_by_institution_type = Application.objects.values('bursary_category__category_type').annotate(count=Count('id'))
    
    context = {
        'total_applications': total_applications,
        'applications_by_status': applications_by_status,
        'applications_by_ward': applications_by_ward,
        'applications_by_institution_type': applications_by_institution_type,
    }
    return render(request, 'admin/application_reports.html', context)

@login_required
@user_passes_test(is_admin)
def financial_reports(request):
    # Financial statistics
    total_allocated = Allocation.objects.aggregate(Sum('amount_allocated'))['amount_allocated__sum'] or 0
    total_disbursed = Allocation.objects.filter(is_disbursed=True).aggregate(Sum('amount_allocated'))['amount_allocated__sum'] or 0
    pending_disbursement = total_allocated - total_disbursed
    
    # Allocations by category
    allocations_by_category = Allocation.objects.values('application__bursary_category__name').annotate(
        total=Sum('amount_allocated'),
        count=Count('id')
    )
    
    context = {
        'total_allocated': total_allocated,
        'total_disbursed': total_disbursed,
        'pending_disbursement': pending_disbursement,
        'allocations_by_category': allocations_by_category,
    }
    return render(request, 'admin/financial_reports.html', context)

# Ward Management Views
@login_required
@user_passes_test(is_admin)
def ward_list(request):
    wards = Ward.objects.all()
    
    context = {'wards': wards}
    return render(request, 'admin/ward_list.html', context)

@login_required
@user_passes_test(is_admin)
def location_list(request, ward_id):
    ward = get_object_or_404(Ward, id=ward_id)
    locations = Location.objects.filter(ward=ward)
    
    context = {
        'ward': ward,
        'locations': locations,
    }
    return render(request, 'admin/location_list.html', context)