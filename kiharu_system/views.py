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
        
        if user is not None and user.user_type in ['admin', 'reviewer', 'finance' , 'applicant']:
            login(request, user)
            # Redirect based on user type
            if user.user_type == 'admin':
                return redirect('admin_dashboard')
            elif user.user_type == 'reviewer':
                return redirect('reviewer_dashboard')
            elif user.user_type == 'finance':
                return redirect('finance_dashboard') 
            elif user.user_type == 'applicant':
                return redirect('student_dashboard') 
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




from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse, HttpResponse
from django.core.paginator import Paginator
from django.db.models import Q, Sum
from django.utils import timezone
from django.conf import settings
import os
from .models import *
from .forms import *  # We'll need to create forms

@login_required
def student_dashboard(request):
    try:
        applicant = request.user.applicant_profile
    except Applicant.DoesNotExist:
        return redirect('student_profile_create')
    
    current_fiscal_year = FiscalYear.objects.filter(is_active=True).first()
    applications = Application.objects.filter(applicant=applicant).order_by('-date_submitted')
    current_application = applications.filter(fiscal_year=current_fiscal_year).first() if current_fiscal_year else None
    
    # Unread notifications
    unread_notifications = Notification.objects.filter(
        user=request.user, 
        is_read=False
    )
    recent_notifications = unread_notifications.order_by('-created_at')[:5]
    
    # Stats
    total_applications = applications.count()
    approved_applications = applications.filter(status='approved').count()
    pending_applications = applications.filter(status__in=['submitted', 'under_review']).count()
    total_received = Allocation.objects.filter(
        application__applicant=applicant
    ).aggregate(total=Sum('amount_allocated'))['total'] or 0
    
    context = {
        'applicant': applicant,
        'current_application': current_application,
        'current_fiscal_year': current_fiscal_year,
        'recent_notifications': recent_notifications,
        'unread_notifications_count': unread_notifications.count(),  # 👈 added
        'total_applications': total_applications,
        'approved_applications': approved_applications,
        'pending_applications': pending_applications,
        'total_received': total_received,
        'recent_applications': applications[:3]
    }
    
    return render(request, 'students/dashboard.html', context)


@login_required
def student_profile_create(request):
    """
    Create or update student profile
    """
    try:
        applicant = request.user.applicant_profile
        is_update = True
    except Applicant.DoesNotExist:
        applicant = None
        is_update = False
    
    if request.method == 'POST':
        form = ApplicantForm(request.POST, instance=applicant)
        if form.is_valid():
            applicant = form.save(commit=False)
            applicant.user = request.user
            applicant.save()
            
            messages.success(request, 'Profile saved successfully!')
            return redirect('student_dashboard')
    else:
        form = ApplicantForm(instance=applicant)
    
    # Get location data for dropdowns
    wards = Ward.objects.all()
    
    context = {
        'form': form,
        'is_update': is_update,
        'wards': wards,
    }
    
    return render(request, 'students/profile_form.html', context)

@login_required
def student_profile_view(request):
    """
    View student profile details
    """
    try:
        applicant = request.user.applicant_profile
    except Applicant.DoesNotExist:
        return redirect('student_profile_create')
    
    guardians = Guardian.objects.filter(applicant=applicant)
    siblings = SiblingInformation.objects.filter(applicant=applicant)
    
    context = {
        'applicant': applicant,
        'guardians': guardians,
        'siblings': siblings,
    }
    
    return render(request, 'students/profile_view.html', context)

@login_required
def student_application_create(request):
    """
    Create new bursary application
    """
    try:
        applicant = request.user.applicant_profile
    except Applicant.DoesNotExist:
        messages.error(request, 'Please complete your profile first.')
        return redirect('student_profile_create')
    
    current_fiscal_year = FiscalYear.objects.filter(is_active=True).first()
    if not current_fiscal_year:
        messages.error(request, 'No active fiscal year found. Applications are currently closed.')
        return redirect('student_dashboard')
    
    # Check if already has application for current year
    existing_application = Application.objects.filter(
        applicant=applicant, 
        fiscal_year=current_fiscal_year
    ).first()
    
    if existing_application:
        messages.info(request, 'You already have an application for this fiscal year.')
        return redirect('student_application_detail', pk=existing_application.pk)
    
    if request.method == 'POST':
        form = ApplicationForm(request.POST)
        if form.is_valid():
            application = form.save(commit=False)
            application.applicant = applicant
            application.fiscal_year = current_fiscal_year
            application.save()
            
            messages.success(request, 'Application created successfully! Please upload required documents.')
            return redirect('application_documents', pk=application.pk)
    else:
        form = ApplicationForm()
    
    # Get available categories and institutions
    categories = BursaryCategory.objects.filter(fiscal_year=current_fiscal_year)
    institutions = Institution.objects.all().order_by('name')
    
    context = {
        'form': form,
        'categories': categories,
        'institutions': institutions,
        'current_fiscal_year': current_fiscal_year,
    }
    
    return render(request, 'students/application_form.html', context)

@login_required
def student_application_list(request):
    """
    List all applications by the student
    """
    try:
        applicant = request.user.applicant_profile
    except Applicant.DoesNotExist:
        return redirect('student_profile_create')
    
    applications = Application.objects.filter(applicant=applicant).order_by('-date_submitted')
    
    # Pagination
    paginator = Paginator(applications, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'applications': page_obj,
    }
    
    return render(request, 'students/application_list.html', context)

@login_required
def student_application_detail(request, pk):
    """
    View application details
    """
    try:
        applicant = request.user.applicant_profile
    except Applicant.DoesNotExist:
        return redirect('student_profile_create')
    
    application = get_object_or_404(Application, pk=pk, applicant=applicant)
    documents = Document.objects.filter(application=application)
    reviews = Review.objects.filter(application=application).order_by('-review_date')
    
    try:
        allocation = Allocation.objects.get(application=application)
    except Allocation.DoesNotExist:
        allocation = None
    
    context = {
        'application': application,
        'documents': documents,
        'reviews': reviews,
        'allocation': allocation,
    }
    
    return render(request, 'students/application_detail.html', context)

@login_required
def student_application_edit(request, pk):
    """
    Edit application (only if in draft status)
    """
    try:
        applicant = request.user.applicant_profile
    except Applicant.DoesNotExist:
        return redirect('student_profile_create')
    
    application = get_object_or_404(Application, pk=pk, applicant=applicant)
    
    if application.status != 'draft':
        messages.error(request, 'You can only edit applications in draft status.')
        return redirect('application_detail', pk=pk)
    
    if request.method == 'POST':
        form = ApplicationForm(request.POST, instance=application)
        if form.is_valid():
            form.save()
            messages.success(request, 'Application updated successfully!')
            return redirect('application_detail', pk=pk)
    else:
        form = ApplicationForm(instance=application)
    
    categories = BursaryCategory.objects.filter(fiscal_year=application.fiscal_year)
    institutions = Institution.objects.all().order_by('name')
    
    context = {
        'form': form,
        'application': application,
        'categories': categories,
        'institutions': institutions,
    }
    
    return render(request, 'students/application_form.html', context)

@login_required
def student_application_documents(request, pk):
    """
    Upload and manage application documents
    """
    try:
        applicant = request.user.applicant_profile
    except Applicant.DoesNotExist:
        return redirect('student_profile_create')
    
    application = get_object_or_404(Application, pk=pk, applicant=applicant)
    
    if request.method == 'POST':
        form = DocumentForm(request.POST, request.FILES)
        if form.is_valid():
            document = form.save(commit=False)
            document.application = application
            document.save()
            messages.success(request, 'Document uploaded successfully!')
            return redirect('application_documents', pk=pk)
    else:
        form = DocumentForm()
    
    documents = Document.objects.filter(application=application)
    
    context = {
        'application': application,
        'documents': documents,
        'form': form,
    }
    
    return render(request, 'students/application_documents.html', context)

@login_required
def student_application_submit(request, pk):
    """
    Submit application for review
    """
    try:
        applicant = request.user.applicant_profile
    except Applicant.DoesNotExist:
        return redirect('student_profile_create')
    
    application = get_object_or_404(Application, pk=pk, applicant=applicant)
    
    if application.status != 'draft':
        messages.error(request, 'Application has already been submitted.')
        return redirect('application_detail', pk=pk)
    
    # Check if required documents are uploaded
    required_docs = ['id_card', 'admission_letter', 'fee_structure', 'fee_statement']
    uploaded_docs = Document.objects.filter(application=application).values_list('document_type', flat=True)
    
    missing_docs = [doc for doc in required_docs if doc not in uploaded_docs]
    
    if missing_docs:
        doc_names = [dict(Document.DOCUMENT_TYPES)[doc] for doc in missing_docs]
        messages.error(request, f'Please upload the following required documents: {", ".join(doc_names)}')
        return redirect('application_documents', pk=pk)
    
    if request.method == 'POST':
        application.status = 'submitted'
        application.save()
        
        # Create notification
        Notification.objects.create(
            user=request.user,
            notification_type='application_status',
            title='Application Submitted',
            message=f'Your application {application.application_number} has been submitted for review.',
            related_application=application
        )
        
        messages.success(request, 'Application submitted successfully!')
        return redirect('application_detail', pk=pk)
    
    context = {
        'application': application,
    }
    
    return render(request, 'students/application_submit_confirm.html', context)

@login_required
def student_guardian_create(request):
    """
    Add guardian information
    """
    try:
        applicant = request.user.applicant_profile
    except Applicant.DoesNotExist:
        return redirect('student_profile_create')
    
    if request.method == 'POST':
        form = GuardianForm(request.POST)
        if form.is_valid():
            guardian = form.save(commit=False)
            guardian.applicant = applicant
            guardian.save()
            messages.success(request, 'Guardian information added successfully!')
            return redirect('student_profile_view')
    else:
        form = GuardianForm()
    
    context = {
        'form': form,
    }
    
    return render(request, 'students/guardian_form.html', context)

@login_required
def student_sibling_create(request):
    """
    Add sibling information
    """
    try:
        applicant = request.user.applicant_profile
    except Applicant.DoesNotExist:
        return redirect('student_profile_create')
    
    if request.method == 'POST':
        form = SiblingForm(request.POST)
        if form.is_valid():
            sibling = form.save(commit=False)
            sibling.applicant = applicant
            sibling.save()
            messages.success(request, 'Sibling information added successfully!')
            return redirect('student_profile_view')
    else:
        form = SiblingForm()
    
    context = {
        'form': form,
    }
    
    return render(request, 'students/sibling_form.html', context)

@login_required
def notifications_list(request):
    """
    List all notifications for the student
    """
    notifications = Notification.objects.filter(user=request.user).order_by('-created_at')
    
    # Mark as read when viewed
    notifications.filter(is_read=False).update(is_read=True)
    
    # Pagination
    paginator = Paginator(notifications, 15)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'notifications': page_obj,
    }
    
    return render(request, 'students/notifications.html', context)

@login_required
def student_document_delete(request, pk):
    """
    Delete a document
    """
    try:
        applicant = request.user.applicant_profile
    except Applicant.DoesNotExist:
        return redirect('student_profile_create')
    
    document = get_object_or_404(Document, pk=pk, application__applicant=applicant)
    
    if document.application.status != 'draft':
        messages.error(request, 'Cannot delete documents from submitted applications.')
        return redirect('application_documents', pk=document.application.pk)
    
    if request.method == 'POST':
        # Delete file from storage
        if document.file:
            if os.path.isfile(document.file.path):
                os.remove(document.file.path)
        
        document.delete()
        messages.success(request, 'Document deleted successfully!')
    
    return redirect('application_documents', pk=document.application.pk)

# AJAX Views
@login_required
def get_locations(request):
    """
    Get locations for a specific ward (AJAX)
    """
    ward_id = request.GET.get('ward_id')
    if ward_id:
        locations = Location.objects.filter(ward_id=ward_id).values('id', 'name')
        return JsonResponse(list(locations), safe=False)
    return JsonResponse([], safe=False)

@login_required
def get_sublocations(request):
    """
    Get sub-locations for a specific location (AJAX)
    """
    location_id = request.GET.get('location_id')
    if location_id:
        sublocations = SubLocation.objects.filter(location_id=location_id).values('id', 'name')
        return JsonResponse(list(sublocations), safe=False)
    return JsonResponse([], safe=False)

@login_required
def get_villages(request):
    """
    Get villages for a specific sub-location (AJAX)
    """
    sublocation_id = request.GET.get('sublocation_id')
    if sublocation_id:
        villages = Village.objects.filter(sublocation_id=sublocation_id).values('id', 'name')
        return JsonResponse(list(villages), safe=False)
    return JsonResponse([], safe=False)

@login_required
def application_status_check(request, pk):
    """
    Check application status (AJAX)
    """
    try:
        applicant = request.user.applicant_profile
        application = get_object_or_404(Application, pk=pk, applicant=applicant)
        
        data = {
            'status': application.status,
            'status_display': application.get_status_display(),
            'last_updated': application.last_updated.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Include allocation info if available
        try:
            allocation = application.allocation
            data['allocation'] = {
                'amount': str(allocation.amount_allocated),
                'date': allocation.allocation_date.strftime('%Y-%m-%d'),
                'is_disbursed': allocation.is_disbursed
            }
        except Allocation.DoesNotExist:
            data['allocation'] = None
            
        return JsonResponse(data)
    except Applicant.DoesNotExist:
        return JsonResponse({'error': 'Profile not found'}, status=404)

def faqs_view(request):
    """
    View FAQ page (accessible to all)
    """
    faqs = FAQ.objects.filter(is_active=True).order_by('order', 'question')
    
    # Group FAQs by category
    faq_categories = {}
    for faq in faqs:
        if faq.category not in faq_categories:
            faq_categories[faq.category] = []
        faq_categories[faq.category].append(faq)
    
    context = {
        'faq_categories': faq_categories,
    }
    
    return render(request, 'students/faqs.html', context)

def announcements_view(request):
    """
    View announcements page
    """
    current_time = timezone.now()
    announcements = Announcement.objects.filter(
        is_active=True,
        published_date__lte=current_time,
        expiry_date__gte=current_time
    ).order_by('-published_date')
    
    context = {
        'announcements': announcements,
    }
    
    return render(request, 'students/announcements.html', context)