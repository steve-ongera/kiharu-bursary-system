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
from django.utils import timezone
from django.http import HttpResponse, HttpResponseForbidden

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
# views.py
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Q
import json
from .models import Institution

@login_required
def institution_list(request):
    """Main institution management page"""
    # Get filter parameters
    search = request.GET.get('search', '')
    institution_type = request.GET.get('type', '')
    county = request.GET.get('county', '')
    
    # Build query
    institutions = Institution.objects.all().order_by('name')
    
    if search:
        institutions = institutions.filter(
            Q(name__icontains=search) | 
            Q(county__icontains=search) |
            Q(postal_address__icontains=search)
        )
    
    if institution_type:
        institutions = institutions.filter(institution_type=institution_type)
    
    if county:
        institutions = institutions.filter(county__icontains=county)
    
    # Pagination
    paginator = Paginator(institutions, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Get unique counties for filter
    counties = Institution.objects.values_list('county', flat=True).distinct().order_by('county')
    
    context = {
        'page_obj': page_obj,
        'counties': counties,
        'search': search,
        'institution_type': institution_type,
        'county': county,
        'institution_types': Institution.INSTITUTION_TYPES,
    }
    
    return render(request, 'institutions/list.html', context)

@login_required
@require_http_methods(["POST"])
@csrf_exempt
def institution_create(request):
    """Create new institution via AJAX"""
    try:
        data = json.loads(request.body)
        
        # Validation
        required_fields = ['name', 'institution_type', 'county']
        for field in required_fields:
            if not data.get(field):
                return JsonResponse({
                    'success': False,
                    'error': f'{field.replace("_", " ").title()} is required'
                })
        
        # Check if institution already exists
        if Institution.objects.filter(
            name=data['name'], 
            institution_type=data['institution_type']
        ).exists():
            return JsonResponse({
                'success': False,
                'error': 'An institution with this name and type already exists'
            })
        
        # Create institution
        institution = Institution.objects.create(
            name=data['name'],
            institution_type=data['institution_type'],
            county=data['county'],
            postal_address=data.get('postal_address', ''),
            phone_number=data.get('phone_number', ''),
            email=data.get('email', '')
        )
        
        return JsonResponse({
            'success': True,
            'message': 'Institution created successfully',
            'institution': {
                'id': institution.id,
                'name': institution.name,
                'institution_type': institution.get_institution_type_display(),
                'county': institution.county,
                'postal_address': institution.postal_address or '-',
                'phone_number': institution.phone_number or '-',
                'email': institution.email or '-'
            }
        })
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON data'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
def institution_detail(request, pk):
    """Get institution details via AJAX"""
    try:
        institution = get_object_or_404(Institution, pk=pk)
        
        return JsonResponse({
            'success': True,
            'institution': {
                'id': institution.id,
                'name': institution.name,
                'institution_type': institution.institution_type,
                'institution_type_display': institution.get_institution_type_display(),
                'county': institution.county,
                'postal_address': institution.postal_address or '',
                'phone_number': institution.phone_number or '',
                'email': institution.email or ''
            }
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
@require_http_methods(["POST"])
@csrf_exempt
def institution_update(request, pk):
    """Update institution via AJAX"""
    try:
        institution = get_object_or_404(Institution, pk=pk)
        data = json.loads(request.body)
        
        # Validation
        required_fields = ['name', 'institution_type', 'county']
        for field in required_fields:
            if not data.get(field):
                return JsonResponse({
                    'success': False,
                    'error': f'{field.replace("_", " ").title()} is required'
                })
        
        # Check if another institution with same name and type exists
        existing = Institution.objects.filter(
            name=data['name'], 
            institution_type=data['institution_type']
        ).exclude(pk=pk)
        
        if existing.exists():
            return JsonResponse({
                'success': False,
                'error': 'Another institution with this name and type already exists'
            })
        
        # Update institution
        institution.name = data['name']
        institution.institution_type = data['institution_type']
        institution.county = data['county']
        institution.postal_address = data.get('postal_address', '')
        institution.phone_number = data.get('phone_number', '')
        institution.email = data.get('email', '')
        institution.save()
        
        return JsonResponse({
            'success': True,
            'message': 'Institution updated successfully',
            'institution': {
                'id': institution.id,
                'name': institution.name,
                'institution_type': institution.get_institution_type_display(),
                'county': institution.county,
                'postal_address': institution.postal_address or '-',
                'phone_number': institution.phone_number or '-',
                'email': institution.email or '-'
            }
        })
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON data'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
@require_http_methods(["POST"])
@csrf_exempt
def institution_delete(request, pk):
    """Delete institution via AJAX"""
    try:
        institution = get_object_or_404(Institution, pk=pk)
        
        # Check if institution is being used in applications
        if institution.application_set.exists():
            return JsonResponse({
                'success': False,
                'error': 'Cannot delete institution as it has associated applications'
            })
        
        institution_name = institution.name
        institution.delete()
        
        return JsonResponse({
            'success': True,
            'message': f'Institution "{institution_name}" deleted successfully'
        })
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
def institution_search(request):
    """Search institutions for autocomplete"""
    query = request.GET.get('q', '')
    institution_type = request.GET.get('type', '')
    
    institutions = Institution.objects.all()
    
    if query:
        institutions = institutions.filter(
            Q(name__icontains=query) | Q(county__icontains=query)
        )
    
    if institution_type:
        institutions = institutions.filter(institution_type=institution_type)
    
    institutions = institutions[:10]  # Limit to 10 results
    
    results = []
    for institution in institutions:
        results.append({
            'id': institution.id,
            'name': institution.name,
            'type': institution.get_institution_type_display(),
            'county': institution.county
        })
    
    return JsonResponse({'results': results})

# User Management Views
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth import get_user_model
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Q, Count
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views.generic import View
from django.contrib.auth.hashers import make_password
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.db import transaction
import json
import secrets
import string
import re
from .models import User, AuditLog

User = get_user_model()

def is_admin(user):
    return user.is_authenticated and user.user_type == 'admin'

class UserManagementView(View):
    """Enhanced User Management with AJAX support"""
    
    @method_decorator(login_required)
    @method_decorator(user_passes_test(is_admin))
    def get(self, request):
        # Get filter parameters
        user_type = request.GET.get('user_type', '')
        search_query = request.GET.get('search', '')
        status = request.GET.get('status', '')
        date_from = request.GET.get('date_from', '')
        date_to = request.GET.get('date_to', '')
        
        # Build queryset with filters
        users = User.objects.all().select_related()
        
        if user_type:
            users = users.filter(user_type=user_type)
            
        if search_query:
            users = users.filter(
                Q(username__icontains=search_query) |
                Q(email__icontains=search_query) |
                Q(first_name__icontains=search_query) |
                Q(last_name__icontains=search_query) |
                Q(id_number__icontains=search_query)
            )
            
        if status:
            if status == 'active':
                users = users.filter(is_active=True)
            elif status == 'inactive':
                users = users.filter(is_active=False)
                
        if date_from:
            users = users.filter(date_joined__gte=date_from)
        if date_to:
            users = users.filter(date_joined__lte=date_to)
        
        # Order by creation date (newest first)
        users = users.order_by('-date_joined')
        
        # Handle AJAX requests for user list
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            page_number = request.GET.get('page', 1)
            paginator = Paginator(users, 10)
            page_obj = paginator.get_page(page_number)
            
            users_data = []
            for user in page_obj:
                users_data.append({
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'full_name': f"{user.first_name} {user.last_name}",
                    'user_type': user.get_user_type_display(),
                    'user_type_value': user.user_type,
                    'phone_number': user.phone_number or '-',
                    'id_number': user.id_number or '-',
                    'is_active': user.is_active,
                    'date_joined': user.date_joined.strftime('%Y-%m-%d %H:%M'),
                    'last_login': user.last_login.strftime('%Y-%m-%d %H:%M') if user.last_login else 'Never',
                })
            
            return JsonResponse({
                'users': users_data,
                'has_next': page_obj.has_next(),
                'has_previous': page_obj.has_previous(),
                'current_page': page_obj.number,
                'total_pages': paginator.num_pages,
                'total_count': paginator.count,
            })
        
        # Regular page load
        paginator = Paginator(users, 10)
        page_number = request.GET.get('page', 1)
        page_obj = paginator.get_page(page_number)
        
        # Get statistics
        stats = {
            'total_users': User.objects.exclude(user_type='applicant').count(),
            'admin_count': User.objects.filter(user_type='admin').count(),
            'reviewer_count': User.objects.filter(user_type='reviewer').count(),
            'finance_count': User.objects.filter(user_type='finance').count(),
            'active_users': User.objects.exclude(user_type='applicant').filter(is_active=True).count(),
        }
        
        context = {
            'page_obj': page_obj,
            'current_filters': {
                'user_type': user_type,
                'search': search_query,
                'status': status,
                'date_from': date_from,
                'date_to': date_to,
            },
            'user_types': User.USER_TYPES,
            'stats': stats,
        }
        
        return render(request, 'admin/user_management.html', context)

@login_required
@user_passes_test(is_admin)
def user_create_ajax(request):
    """Create user via AJAX with enhanced validation"""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            
            # Extract data
            username = data.get('username', '').strip()
            email = data.get('email', '').strip()
            first_name = data.get('first_name', '').strip()
            last_name = data.get('last_name', '').strip()
            user_type = data.get('user_type', '')
            id_number = data.get('id_number', '').strip()
            phone_number = data.get('phone_number', '').strip()
            generate_password = data.get('generate_password', False)
            custom_password = data.get('custom_password', '')
            
            # Validation
            errors = {}
            
            # Username validation
            if not username:
                errors['username'] = 'Username is required'
            elif len(username) < 3:
                errors['username'] = 'Username must be at least 3 characters'
            elif User.objects.filter(username=username).exists():
                errors['username'] = 'Username already exists'
            elif not re.match(r'^[a-zA-Z0-9_]+$', username):
                errors['username'] = 'Username can only contain letters, numbers, and underscores'
            
            # Email validation
            if not email:
                errors['email'] = 'Email is required'
            else:
                try:
                    validate_email(email)
                    if User.objects.filter(email=email).exists():
                        errors['email'] = 'Email already exists'
                except ValidationError:
                    errors['email'] = 'Invalid email format'
            
            # Name validation
            if not first_name:
                errors['first_name'] = 'First name is required'
            if not last_name:
                errors['last_name'] = 'Last name is required'
            
            # User type validation
            if not user_type or user_type not in dict(User.USER_TYPES).keys():
                errors['user_type'] = 'Valid user type is required'
            
            # ID number validation
            if id_number:
                if not re.match(r'^\d{7,8}$', id_number):
                    errors['id_number'] = 'ID number must be 7-8 digits'
                elif User.objects.filter(id_number=id_number).exists():
                    errors['id_number'] = 'ID number already exists'
            
            # Phone validation
            if phone_number:
                if not re.match(r'^\+254\d{9}$', phone_number):
                    errors['phone_number'] = 'Phone must be in format +254XXXXXXXXX'
                elif User.objects.filter(phone_number=phone_number).exists():
                    errors['phone_number'] = 'Phone number already exists'
            
            # Password validation
            if generate_password:
                # Generate secure password
                password = generate_secure_password()
            elif custom_password:
                if len(custom_password) < 8:
                    errors['custom_password'] = 'Password must be at least 8 characters'
                password = custom_password
            else:
                errors['password'] = 'Password is required'
                password = None
            
            if errors:
                return JsonResponse({
                    'success': False,
                    'errors': errors
                }, status=400)
            
            # Create user with transaction
            with transaction.atomic():
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    first_name=first_name,
                    last_name=last_name,
                    user_type=user_type,
                    password=password,
                    id_number=id_number if id_number else None,
                    phone_number=phone_number if phone_number else '',
                    is_active=True
                )
                
                # Log the action
                AuditLog.objects.create(
                    user=request.user,
                    action='create',
                    table_affected='User',
                    record_id=str(user.id),
                    description=f'Created user: {username} ({user_type})',
                    ip_address=get_client_ip(request)
                )
            
            return JsonResponse({
                'success': True,
                'message': 'User created successfully',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'full_name': f"{user.first_name} {user.last_name}",
                    'user_type': user.get_user_type_display(),
                },
                'generated_password': password if generate_password else None
            })
            
        except json.JSONDecodeError:
            return JsonResponse({
                'success': False,
                'message': 'Invalid JSON data'
            }, status=400)
        except Exception as e:
            return JsonResponse({
                'success': False,
                'message': f'Error creating user: {str(e)}'
            }, status=500)
    
    return JsonResponse({'success': False, 'message': 'Invalid request method'}, status=405)

@login_required
@user_passes_test(is_admin)
def user_detail_ajax(request, user_id):
    """Get user details via AJAX"""
    try:
        user = get_object_or_404(User, id=user_id)
        
        return JsonResponse({
            'success': True,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'user_type': user.user_type,
                'user_type_display': user.get_user_type_display(),
                'id_number': user.id_number or '',
                'phone_number': user.phone_number or '',
                'is_active': user.is_active,
                'date_joined': user.date_joined.strftime('%Y-%m-%d %H:%M:%S'),
                'last_login': user.last_login.strftime('%Y-%m-%d %H:%M:%S') if user.last_login else None,
            }
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f'Error fetching user: {str(e)}'
        }, status=500)

@login_required
@user_passes_test(is_admin)
def user_update_ajax(request, user_id):
    """Update user via AJAX"""
    if request.method == 'POST':
        try:
            user = get_object_or_404(User, id=user_id)
            data = json.loads(request.body)
            
            # Extract data
            email = data.get('email', '').strip()
            first_name = data.get('first_name', '').strip()
            last_name = data.get('last_name', '').strip()
            user_type = data.get('user_type', '')
            id_number = data.get('id_number', '').strip()
            phone_number = data.get('phone_number', '').strip()
            is_active = data.get('is_active', True)
            
            # Validation
            errors = {}
            
            # Email validation
            if not email:
                errors['email'] = 'Email is required'
            else:
                try:
                    validate_email(email)
                    if User.objects.filter(email=email).exclude(id=user.id).exists():
                        errors['email'] = 'Email already exists'
                except ValidationError:
                    errors['email'] = 'Invalid email format'
            
            # Name validation
            if not first_name:
                errors['first_name'] = 'First name is required'
            if not last_name:
                errors['last_name'] = 'Last name is required'
            
            # User type validation
            if not user_type or user_type not in dict(User.USER_TYPES).keys():
                errors['user_type'] = 'Valid user type is required'
            
            # ID number validation
            if id_number:
                if not re.match(r'^\d{7,8}$', id_number):
                    errors['id_number'] = 'ID number must be 7-8 digits'
                elif User.objects.filter(id_number=id_number).exclude(id=user.id).exists():
                    errors['id_number'] = 'ID number already exists'
            
            # Phone validation
            if phone_number:
                if not re.match(r'^\+254\d{9}$', phone_number):
                    errors['phone_number'] = 'Phone must be in format +254XXXXXXXXX'
                elif User.objects.filter(phone_number=phone_number).exclude(id=user.id).exists():
                    errors['phone_number'] = 'Phone number already exists'
            
            if errors:
                return JsonResponse({
                    'success': False,
                    'errors': errors
                }, status=400)
            
            # Update user
            with transaction.atomic():
                user.email = email
                user.first_name = first_name
                user.last_name = last_name
                user.user_type = user_type
                user.id_number = id_number if id_number else None
                user.phone_number = phone_number
                user.is_active = is_active
                user.save()
                
                # Log the action
                AuditLog.objects.create(
                    user=request.user,
                    action='update',
                    table_affected='User',
                    record_id=str(user.id),
                    description=f'Updated user: {user.username}',
                    ip_address=get_client_ip(request)
                )
            
            return JsonResponse({
                'success': True,
                'message': 'User updated successfully',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'full_name': f"{user.first_name} {user.last_name}",
                    'user_type': user.get_user_type_display(),
                    'is_active': user.is_active,
                }
            })
            
        except json.JSONDecodeError:
            return JsonResponse({
                'success': False,
                'message': 'Invalid JSON data'
            }, status=400)
        except Exception as e:
            return JsonResponse({
                'success': False,
                'message': f'Error updating user: {str(e)}'
            }, status=500)
    
    return JsonResponse({'success': False, 'message': 'Invalid request method'}, status=405)

@login_required
@user_passes_test(is_admin)
def user_delete_ajax(request, user_id):
    """Delete user via AJAX"""
    if request.method == 'POST':
        try:
            user = get_object_or_404(User, id=user_id)
            
            # Prevent deleting self
            if user.id == request.user.id:
                return JsonResponse({
                    'success': False,
                    'message': 'You cannot delete yourself'
                }, status=400)
            
            # Check if user has related data (you might want to implement soft delete)
            username = user.username
            
            with transaction.atomic():
                # Log before deletion
                AuditLog.objects.create(
                    user=request.user,
                    action='delete',
                    table_affected='User',
                    record_id=str(user.id),
                    description=f'Deleted user: {username}',
                    ip_address=get_client_ip(request)
                )
                
                user.delete()
            
            return JsonResponse({
                'success': True,
                'message': f'User {username} deleted successfully'
            })
            
        except Exception as e:
            return JsonResponse({
                'success': False,
                'message': f'Error deleting user: {str(e)}'
            }, status=500)
    
    return JsonResponse({'success': False, 'message': 'Invalid request method'}, status=405)

@login_required
@user_passes_test(is_admin)
def user_reset_password_ajax(request, user_id):
    """Reset user password via AJAX"""
    if request.method == 'POST':
        try:
            user = get_object_or_404(User, id=user_id)
            data = json.loads(request.body)
            
            generate_password = data.get('generate_password', False)
            custom_password = data.get('custom_password', '')
            
            if generate_password:
                new_password = generate_secure_password()
            elif custom_password:
                if len(custom_password) < 8:
                    return JsonResponse({
                        'success': False,
                        'message': 'Password must be at least 8 characters'
                    }, status=400)
                new_password = custom_password
            else:
                return JsonResponse({
                    'success': False,
                    'message': 'Password is required'
                }, status=400)
            
            with transaction.atomic():
                user.set_password(new_password)
                user.save()
                
                # Log the action
                AuditLog.objects.create(
                    user=request.user,
                    action='update',
                    table_affected='User',
                    record_id=str(user.id),
                    description=f'Reset password for user: {user.username}',
                    ip_address=get_client_ip(request)
                )
            
            return JsonResponse({
                'success': True,
                'message': 'Password reset successfully',
                'generated_password': new_password if generate_password else None
            })
            
        except json.JSONDecodeError:
            return JsonResponse({
                'success': False,
                'message': 'Invalid JSON data'
            }, status=400)
        except Exception as e:
            return JsonResponse({
                'success': False,
                'message': f'Error resetting password: {str(e)}'
            }, status=500)
    
    return JsonResponse({'success': False, 'message': 'Invalid request method'}, status=405)

def generate_secure_password(length=12):
    """Generate a secure random password"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password

def get_client_ip(request):
    """Get client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip



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

# Report graphs  Views

from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.db.models import Sum, Count, Avg, Q
from django.http import JsonResponse
from django.utils import timezone
from datetime import datetime, timedelta
from decimal import Decimal
import json

from .models import (
    Application, Allocation, Applicant, Ward, Institution, 
    FiscalYear, BursaryCategory, Guardian, User
)

@login_required
def application_reports(request):
    """Application Reports Dashboard"""
    # Get current fiscal year
    current_fiscal_year = FiscalYear.objects.filter(is_active=True).first()
    
    # Application status distribution
    status_data = Application.objects.filter(
        fiscal_year=current_fiscal_year
    ).values('status').annotate(
        count=Count('id')
    ).order_by('status')
    
    # Applications by category
    category_data = Application.objects.filter(
        fiscal_year=current_fiscal_year
    ).values('bursary_category__name').annotate(
        count=Count('id')
    ).order_by('bursary_category__name')
    
    # Monthly application trends
    monthly_data = []
    for i in range(12):
        month_start = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0) - timedelta(days=30*i)
        month_end = (month_start + timedelta(days=32)).replace(day=1) - timedelta(seconds=1)
        
        count = Application.objects.filter(
            date_submitted__range=[month_start, month_end],
            fiscal_year=current_fiscal_year
        ).count()
        
        monthly_data.append({
            'month': month_start.strftime('%B %Y'),
            'count': count
        })
    
    monthly_data.reverse()
    
    # Summary statistics
    total_applications = Application.objects.filter(fiscal_year=current_fiscal_year).count()
    approved_applications = Application.objects.filter(
        fiscal_year=current_fiscal_year, status='approved'
    ).count()
    pending_applications = Application.objects.filter(
        fiscal_year=current_fiscal_year, status__in=['submitted', 'under_review']
    ).count()
    rejected_applications = Application.objects.filter(
        fiscal_year=current_fiscal_year, status='rejected'
    ).count()
    
    context = {
        'status_data': json.dumps(list(status_data)),
        'category_data': json.dumps(list(category_data)),
        'monthly_data': json.dumps(monthly_data),
        'total_applications': total_applications,
        'approved_applications': approved_applications,
        'pending_applications': pending_applications,
        'rejected_applications': rejected_applications,
        'current_fiscal_year': current_fiscal_year,
        'report_type': 'applications'
    }
    
    return render(request, 'admin/application_reports.html', context)

from django.core.serializers.json import DjangoJSONEncoder

@login_required
def financial_reports(request):
    """Financial Reports Dashboard"""
    current_fiscal_year = FiscalYear.objects.filter(is_active=True).first()
    
    # Budget allocation by category
    budget_data = BursaryCategory.objects.filter(
        fiscal_year=current_fiscal_year
    ).values('name', 'allocation_amount').annotate(
        disbursed=Sum('application__allocation__amount_allocated', 
                     filter=Q(application__allocation__is_disbursed=True))
    )
    
    for item in budget_data:
        if item['disbursed'] is None:
            item['disbursed'] = 0
        item['remaining'] = float(item['allocation_amount']) - float(item['disbursed'])
    
    # Monthly disbursements
    monthly_disbursements = []
    for i in range(12):
        month_start = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0) - timedelta(days=30*i)
        month_end = (month_start + timedelta(days=32)).replace(day=1) - timedelta(seconds=1)
        
        amount = Allocation.objects.filter(
            disbursement_date__range=[month_start, month_end],
            is_disbursed=True
        ).aggregate(Sum('amount_allocated'))['amount_allocated__sum'] or 0
        
        monthly_disbursements.append({
            'month': month_start.strftime('%B %Y'),
            'amount': float(amount)
        })
    
    monthly_disbursements.reverse()
    
    # Amount requested vs allocated
    request_vs_allocated = Application.objects.filter(
        fiscal_year=current_fiscal_year,
        status='approved'
    ).aggregate(
        total_requested=Sum('amount_requested'),
        total_allocated=Sum('allocation__amount_allocated')
    )
    
    # Financial summary
    total_budget = current_fiscal_year.total_allocation if current_fiscal_year else 0
    total_allocated = Allocation.objects.filter(
        application__fiscal_year=current_fiscal_year
    ).aggregate(Sum('amount_allocated'))['amount_allocated__sum'] or 0
    
    total_disbursed = Allocation.objects.filter(
        application__fiscal_year=current_fiscal_year,
        is_disbursed=True
    ).aggregate(Sum('amount_allocated'))['amount_allocated__sum'] or 0
    
    pending_disbursements = total_allocated - total_disbursed
    
    context = {
        'budget_data': json.dumps(list(budget_data), cls=DjangoJSONEncoder),
        'monthly_disbursements': json.dumps(monthly_disbursements, cls=DjangoJSONEncoder),
        'request_vs_allocated': request_vs_allocated,
        'total_budget': float(total_budget),
        'total_allocated': float(total_allocated),
        'total_disbursed': float(total_disbursed),
        'pending_disbursements': float(pending_disbursements),
        'budget_utilization': round((float(total_allocated) / float(total_budget) * 100), 2) if total_budget > 0 else 0,
        'current_fiscal_year': current_fiscal_year,
        'report_type': 'financial'
    }
    
    return render(request, 'admin/financial_reports.html', context)

@login_required
def ward_reports(request):
    """Ward-based Reports Dashboard"""
    current_fiscal_year = FiscalYear.objects.filter(is_active=True).first()
    
    # Applications by ward
    ward_applications = Ward.objects.annotate(
        total_applications=Count('residents__applications', 
                               filter=Q(residents__applications__fiscal_year=current_fiscal_year)),
        approved_applications=Count('residents__applications',
                                  filter=Q(residents__applications__fiscal_year=current_fiscal_year,
                                          residents__applications__status='approved')),
        total_allocated=Sum('residents__applications__allocation__amount_allocated',
                          filter=Q(residents__applications__fiscal_year=current_fiscal_year,
                                  residents__applications__allocation__is_disbursed=True))
    ).values('name', 'total_applications', 'approved_applications', 'total_allocated')
    
    # Clean up None values
    for ward in ward_applications:
        if ward['total_allocated'] is None:
            ward['total_allocated'] = 0
        else:
            ward['total_allocated'] = float(ward['total_allocated'])
    
    # Gender distribution by ward
    ward_gender_data = []
    for ward in Ward.objects.all():
        male_count = Applicant.objects.filter(
            ward=ward,
            gender='M',
            applications__fiscal_year=current_fiscal_year
        ).count()
        
        female_count = Applicant.objects.filter(
            ward=ward,
            gender='F',
            applications__fiscal_year=current_fiscal_year
        ).count()
        
        if male_count > 0 or female_count > 0:
            ward_gender_data.append({
                'ward': ward.name,
                'male': male_count,
                'female': female_count
            })
    
    # Success rate by ward
    ward_success_rate = []
    for ward in Ward.objects.all():
        total_apps = Application.objects.filter(
            applicant__ward=ward,
            fiscal_year=current_fiscal_year
        ).count()
        
        approved_apps = Application.objects.filter(
            applicant__ward=ward,
            fiscal_year=current_fiscal_year,
            status='approved'
        ).count()
        
        if total_apps > 0:
            success_rate = round((approved_apps / total_apps) * 100, 2)
            ward_success_rate.append({
                'ward': ward.name,
                'success_rate': success_rate,
                'total_applications': total_apps,
                'approved_applications': approved_apps
            })
    
    context = {
        'ward_applications': json.dumps(list(ward_applications)),
        'ward_gender_data': json.dumps(ward_gender_data),
        'ward_success_rate': json.dumps(ward_success_rate),
        'total_wards': Ward.objects.count(),
        'current_fiscal_year': current_fiscal_year,
        'report_type': 'ward'
    }
    
    return render(request, 'admin/ward_reports.html', context)

@login_required
def institution_reports(request):
    """Institution-based Reports Dashboard"""
    current_fiscal_year = FiscalYear.objects.filter(is_active=True).first()
    
    # Applications by institution type
    institution_type_data = Institution.objects.values('institution_type').annotate(
        total_applications=Count('application',
                               filter=Q(application__fiscal_year=current_fiscal_year)),
        approved_applications=Count('application',
                                  filter=Q(application__fiscal_year=current_fiscal_year,
                                          application__status='approved')),
        total_allocated=Sum('application__allocation__amount_allocated',
                          filter=Q(application__fiscal_year=current_fiscal_year,
                                  application__allocation__is_disbursed=True))
    )
    
    # Clean up data
    for item in institution_type_data:
        if item['total_allocated'] is None:
            item['total_allocated'] = 0
        else:
            item['total_allocated'] = float(item['total_allocated'])
    
    # Top institutions by applications
    top_institutions = Institution.objects.annotate(
        application_count=Count('application',
                              filter=Q(application__fiscal_year=current_fiscal_year))
    ).filter(application_count__gt=0).order_by('-application_count')[:10]
    
    top_institutions_data = []
    for inst in top_institutions:
        allocated = Allocation.objects.filter(
            application__institution=inst,
            application__fiscal_year=current_fiscal_year,
            is_disbursed=True
        ).aggregate(Sum('amount_allocated'))['amount_allocated__sum'] or 0
        
        top_institutions_data.append({
            'name': inst.name,
            'type': inst.get_institution_type_display(),
            'applications': inst.application_count,
            'allocated': float(allocated)
        })
    
    # Average allocation by institution type
    avg_allocation_data = []
    for inst_type, display_name in Institution.INSTITUTION_TYPES:
        avg_amount = Allocation.objects.filter(
            application__institution__institution_type=inst_type,
            application__fiscal_year=current_fiscal_year,
            is_disbursed=True
        ).aggregate(Avg('amount_allocated'))['amount_allocated__avg']
        
        if avg_amount:
            avg_allocation_data.append({
                'type': display_name,
                'average': float(avg_amount)
            })
    
    context = {
        'institution_type_data': json.dumps(list(institution_type_data)),
        'top_institutions_data': json.dumps(top_institutions_data),
        'avg_allocation_data': json.dumps(avg_allocation_data),
        'total_institutions': Institution.objects.count(),
        'current_fiscal_year': current_fiscal_year,
        'report_type': 'institution'
    }
    
    return render(request, 'admin/institution_reports.html', context)

@login_required
def performance_reports(request):
    """System Performance Reports Dashboard"""
    current_fiscal_year = FiscalYear.objects.filter(is_active=True).first()
    
    # Processing time analysis (days from submission to approval)
    processing_times = []
    approved_apps = Application.objects.filter(
        fiscal_year=current_fiscal_year,
        status='approved'
    ).select_related('allocation')
    
    for app in approved_apps:
        if app.allocation:
            days_to_process = (app.allocation.allocation_date - app.date_submitted.date()).days
            processing_times.append({
                'application': app.application_number,
                'days': days_to_process,
                'category': app.bursary_category.name
            })
    
    # Reviewer performance
    reviewer_performance = User.objects.filter(
        user_type='reviewer',
        reviews__application__fiscal_year=current_fiscal_year
    ).annotate(
        reviews_count=Count('reviews'),
        approved_count=Count('reviews', filter=Q(reviews__recommendation='approve')),
        rejected_count=Count('reviews', filter=Q(reviews__recommendation='reject'))
    ).values('username', 'first_name', 'last_name', 'reviews_count', 'approved_count', 'rejected_count')
    
    # Monthly performance metrics
    monthly_performance = []
    for i in range(12):
        month_start = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0) - timedelta(days=30*i)
        month_end = (month_start + timedelta(days=32)).replace(day=1) - timedelta(seconds=1)
        
        submitted = Application.objects.filter(
            date_submitted__range=[month_start, month_end],
            fiscal_year=current_fiscal_year
        ).count()
        
        processed = Application.objects.filter(
            fiscal_year=current_fiscal_year,
            allocation__allocation_date__range=[month_start.date(), month_end.date()]
        ).count()
        
        monthly_performance.append({
            'month': month_start.strftime('%B %Y'),
            'submitted': submitted,
            'processed': processed
        })
    
    monthly_performance.reverse()
    
    # Success rates by category
    category_success_rates = []
    for category in BursaryCategory.objects.filter(fiscal_year=current_fiscal_year):
        total_apps = Application.objects.filter(
            bursary_category=category,
            fiscal_year=current_fiscal_year
        ).count()
        
        approved_apps = Application.objects.filter(
            bursary_category=category,
            fiscal_year=current_fiscal_year,
            status='approved'
        ).count()
        
        if total_apps > 0:
            success_rate = round((approved_apps / total_apps) * 100, 2)
            category_success_rates.append({
                'category': category.name,
                'success_rate': success_rate,
                'total': total_apps,
                'approved': approved_apps
            })
    
    # Calculate averages
    avg_processing_time = sum([pt['days'] for pt in processing_times]) / len(processing_times) if processing_times else 0
    
    context = {
        'processing_times': json.dumps(processing_times),
        'reviewer_performance': json.dumps(list(reviewer_performance)),
        'monthly_performance': json.dumps(monthly_performance),
        'category_success_rates': json.dumps(category_success_rates),
        'avg_processing_time': round(avg_processing_time, 2),
        'total_reviewers': User.objects.filter(user_type='reviewer').count(),
        'current_fiscal_year': current_fiscal_year,
        'report_type': 'performance'
    }
    
    return render(request, 'admin/performance_reports.html', context)

# API endpoints for dynamic chart updates
@login_required
def chart_data_api(request, chart_type):
    """API endpoint for dynamic chart data"""
    current_fiscal_year = FiscalYear.objects.filter(is_active=True).first()
    
    if chart_type == 'application_status':
        data = Application.objects.filter(
            fiscal_year=current_fiscal_year
        ).values('status').annotate(count=Count('id'))
        return JsonResponse(list(data), safe=False)
    
    elif chart_type == 'budget_utilization':
        data = BursaryCategory.objects.filter(
            fiscal_year=current_fiscal_year
        ).values('name', 'allocation_amount').annotate(
            disbursed=Sum('application__allocation__amount_allocated',
                         filter=Q(application__allocation__is_disbursed=True))
        )
        return JsonResponse(list(data), safe=False)
    
    # Add more chart types as needed
    return JsonResponse({'error': 'Invalid chart type'}, status=400)

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

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from .models import Applicant, Application, FiscalYear, BursaryCategory, Institution
from .forms import ApplicationForm  # Make sure to import your form

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from .models import Applicant, Application, FiscalYear, BursaryCategory, Institution
from .forms import ApplicationForm  # Make sure to import your form

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
        form = ApplicationForm(request.POST, fiscal_year=current_fiscal_year)
        
        if form.is_valid():
            try:
                application = form.save(commit=False)
                application.applicant = applicant
                application.fiscal_year = current_fiscal_year
                
                # Calculate fees_balance
                application.fees_balance = application.total_fees_payable - application.fees_paid
                
                application.save()
                
                messages.success(request, 'Application created successfully! Please upload required documents.')
                return redirect('application_documents', pk=application.pk)
                
            except Exception as e:
                messages.error(request, f'Error saving application: {str(e)}')
        else:
            # Form has validation errors - they will be displayed in template
            messages.error(request, 'Please correct the errors below.')
    else:
        form = ApplicationForm(fiscal_year=current_fiscal_year)
    
    # Get available categories and institutions for context
    categories = BursaryCategory.objects.filter(fiscal_year=current_fiscal_year)
    institutions = Institution.objects.all().order_by('name')
    
    context = {
        'form': form,
        'categories': categories,
        'institutions': institutions,
        'current_fiscal_year': current_fiscal_year,
    }
    
    return render(request, 'students/application_form.html', context)


# Helper view to get category max amounts via AJAX
@login_required
def get_category_max_amount(request):
    """
    AJAX endpoint to get maximum amount for a category
    """
    if request.method == 'GET' and request.headers.get('x-requested-with') == 'XMLHttpRequest':
        category_id = request.GET.get('category_id')
        if category_id:
            try:
                category = BursaryCategory.objects.get(id=category_id)
                return JsonResponse({
                    'max_amount': float(category.max_amount_per_applicant),
                    'success': True
                })
            except BursaryCategory.DoesNotExist:
                return JsonResponse({'success': False, 'error': 'Category not found'})
    return JsonResponse({'success': False, 'error': 'Invalid request'})

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
            return redirect('student_application_documents', pk=pk)
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
    Submit application for review with enhanced document checking
    """
    try:
        applicant = request.user.applicant_profile
    except Applicant.DoesNotExist:
        messages.error(request, 'Please complete your profile first.')
        return redirect('student_profile_create')
    
    application = get_object_or_404(Application, pk=pk, applicant=applicant)
    
    if application.status != 'draft':
        messages.error(request, 'Application has already been submitted.')
        return redirect('student_application_detail', pk=pk)
    
    # Get all uploaded documents for this application
    uploaded_documents = Document.objects.filter(application=application)
    
    # Define required documents based on application type
    required_docs = ['id_card', 'admission_letter', 'fee_structure', 'fee_statement']
    
    # Add conditional required documents
    if application.applicant.special_needs:
        required_docs.append('medical_report')
    
    if application.is_orphan:
        required_docs.append('death_certificate')
    
    # Check for missing documents
    uploaded_doc_types = uploaded_documents.values_list('document_type', flat=True)
    missing_docs = [doc for doc in required_docs if doc not in uploaded_doc_types]
    
    # Prepare document data for template
    all_document_types = dict(Document.DOCUMENT_TYPES)
    documents_data = []
    
    for doc_type in required_docs:
        doc_obj = uploaded_documents.filter(document_type=doc_type).first()
        
        # Determine file type for preview
        file_type = None
        if doc_obj and doc_obj.file:
            file_extension = doc_obj.file.name.lower().split('.')[-1]
            if file_extension in ['jpg', 'jpeg', 'png', 'gif', 'webp']:
                file_type = 'image'
            elif file_extension == 'pdf':
                file_type = 'pdf'
            else:
                file_type = 'other'
        
        documents_data.append({
            'name': all_document_types.get(doc_type, doc_type.replace('_', ' ').title()),
            'type': doc_type,
            'uploaded': doc_obj is not None,
            'file_url': doc_obj.file.url if doc_obj and doc_obj.file else None,
            'file_type': file_type,
            'upload_date': doc_obj.uploaded_at if doc_obj else None,
            'file_size': doc_obj.file.size if doc_obj and doc_obj.file else None,
        })
    
    # If there are missing documents, redirect back to documents upload
    if missing_docs:
        doc_names = [all_document_types.get(doc, doc.replace('_', ' ').title()) for doc in missing_docs]
        messages.error(
            request, 
            f'Please upload the following required documents before submitting: {", ".join(doc_names)}'
        )
        return redirect('student_application_documents', pk=pk)
    
    if request.method == 'POST':
        try:
            # Update application status
            application.status = 'submitted'
            application.date_submitted = timezone.now()
            application.save()
            
            # Create notification for applicant
            Notification.objects.create(
                user=request.user,
                notification_type='application_status',
                title='Application Submitted Successfully',
                message=f'Your bursary application {application.application_number} has been submitted and is now under review. You will be notified of any status updates.',
                related_application=application
            )
            
            # Create audit log entry
            AuditLog.objects.create(
                user=request.user,
                action='submit',
                table_affected='Application',
                record_id=str(application.pk),
                description=f'Application {application.application_number} submitted for review',
                ip_address=get_client_ip(request)
            )
            
            # Send SMS notification if phone number is available
            if request.user.applicant_profile.user.phone_number:
                try:
                    sms_message = f"Dear {request.user.first_name}, your bursary application {application.application_number} has been submitted successfully. You will be notified of the review outcome. - Kiharu CDF"
                    
                    # Log SMS (implement actual SMS sending based on your SMS provider)
                    SMSLog.objects.create(
                        recipient=request.user,
                        phone_number=request.user.applicant_profile.user.phone_number,
                        message=sms_message,
                        related_application=application,
                        status='pending'
                    )
                    
                    # TODO: Implement actual SMS sending here
                    # send_sms(request.user.applicant_profile.user.phone_number, sms_message)
                    
                except Exception as e:
                    # Log SMS error but don't fail the submission
                    print(f"SMS sending failed: {e}")
            
            messages.success(
                request, 
                f'Application {application.application_number} submitted successfully! '
                'You will receive notifications about the review progress.'
            )
            return redirect('student_application_detail', pk=pk)
            
        except Exception as e:
            messages.error(request, f'Error submitting application: {str(e)}')
            return redirect('student_application_submit', pk=pk)
    
    # Calculate total file size for display
    total_file_size = sum([doc.get('file_size', 0) for doc in documents_data if doc['file_size']])
    
    context = {
        'application': application,
        'documents_data': documents_data,
        'total_documents': len(documents_data),
        'uploaded_documents': len([doc for doc in documents_data if doc['uploaded']]),
        'total_file_size': total_file_size,
        'can_submit': len(missing_docs) == 0,
    }
    
    return render(request, 'students/application_submit_confirm.html', context)


def get_client_ip(request):
    """
    Get client IP address from request
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


@login_required
def document_preview(request, application_id, document_id):
    """
    Serve document files for preview (with access control)
    """
    try:
        applicant = request.user.applicant_profile
        application = get_object_or_404(Application, pk=application_id, applicant=applicant)
        document = get_object_or_404(Document, pk=document_id, application=application)
        
        # Create audit log for document access
        AuditLog.objects.create(
            user=request.user,
            action='view',
            table_affected='Document',
            record_id=str(document.pk),
            description=f'Viewed document {document.get_document_type_display()}',
            ip_address=get_client_ip(request)
        )
        
        # Serve the file
        response = HttpResponse(document.file.read(), content_type='application/octet-stream')
        response['Content-Disposition'] = f'inline; filename="{document.file.name}"'
        
        # Set appropriate content type based on file extension
        file_extension = document.file.name.lower().split('.')[-1]
        content_types = {
            'pdf': 'application/pdf',
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'png': 'image/png',
            'gif': 'image/gif',
            'webp': 'image/webp'
        }
        
        if file_extension in content_types:
            response['Content-Type'] = content_types[file_extension]
        
        return response
        
    except (Applicant.DoesNotExist, Application.DoesNotExist, Document.DoesNotExist):
        return HttpResponseForbidden("You don't have permission to access this document.")

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
        return redirect('student_application_documents', pk=document.application.pk)
    
    if request.method == 'POST':
        # Delete file from storage
        if document.file:
            if os.path.isfile(document.file.path):
                os.remove(document.file.path)
        
        document.delete()
        messages.success(request, 'Document deleted successfully!')
    
    return redirect('student_application_documents', pk=document.application.pk)

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