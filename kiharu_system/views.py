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
from django.core.mail import send_mail
from django.conf import settings
from datetime import timedelta
import logging

logger = logging.getLogger(__name__)

def get_client_ip(request):
    """Get client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def get_session_key(request):
    """Get or create session key"""
    if not hasattr(request.session, 'session_key') or not request.session.session_key:
        # Force session creation if it doesn't exist
        request.session.create()
    return request.session.session_key or 'no-session'

def send_security_email(user, subject, message):
    """Send security notification email"""
    try:
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )
        return True
    except Exception as e:
        logger.error(f"Failed to send security email to {user.email}: {str(e)}")
        return False

def create_security_notification(user, notification_type, ip_address, message):
    """Create a security notification record"""
    notification = SecurityNotification.objects.create(
        user=user,
        notification_type=notification_type,
        ip_address=ip_address,
        message=message
    )
    
    # Send email notification
    subject_map = {
        'failed_login': 'Security Alert: Failed Login Attempt',
        'account_locked': 'Security Alert: Account Locked',
        'tfa_code': 'Your 2FA Verification Code',
        'successful_login': 'Security: Successful Login',
        'account_unlocked': 'Security: Account Unlocked'
    }
    
    subject = subject_map.get(notification_type, 'Security Notification')
    email_sent = send_security_email(user, subject, message)
    
    if email_sent:
        notification.email_sent = True
        notification.email_sent_at = timezone.now()
        notification.save()

def check_account_lock(username, ip_address=None):
    """Check if account is locked and return lock status"""
    try:
        user = User.objects.get(username=username)
        account_lock, created = AccountLock.objects.get_or_create(
            user=user,
            defaults={
                'failed_attempts': 0, 
                'is_locked': False,
                'last_attempt_ip': ip_address or '127.0.0.1'
            }
        )
        
        if account_lock.is_account_locked():
            return True, account_lock, user
        return False, account_lock, user
    except User.DoesNotExist:
        return False, None, None

def handle_failed_login(username, ip_address, user_agent):
    """Handle failed login attempt"""
    # Log the attempt
    LoginAttempt.objects.create(
        username=username,
        ip_address=ip_address,
        success=False,
        user_agent=user_agent
    )
    
    try:
        user = User.objects.get(username=username)
        # Only handle locking for admin users
        if user.user_type in ['admin', 'reviewer', 'finance']:
            account_lock, created = AccountLock.objects.get_or_create(
                user=user,
                defaults={'failed_attempts': 0, 'is_locked': False, 'last_attempt_ip': ip_address}
            )
            
            account_lock.failed_attempts += 1
            account_lock.last_attempt_ip = ip_address
            
            if account_lock.failed_attempts >= 3:
                account_lock.is_locked = True
                account_lock.unlock_time = timezone.now() + timedelta(minutes=15)  # Lock for 15 minutes
                account_lock.save()
                
                # Send security notification
                message = f"""
Security Alert: Your account has been locked due to multiple failed login attempts.

Details:
- Time: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}
- IP Address: {ip_address}
- Failed Attempts: {account_lock.failed_attempts}

Your account will be automatically unlocked after 15 minutes, or contact the system administrator.

If this wasn't you, please contact support immediately.
                """.strip()
                
                create_security_notification(user, 'account_locked', ip_address, message)
                return True  # Account was locked
            else:
                account_lock.save()
                
                # Send failed attempt notification
                attempts_left = 3 - account_lock.failed_attempts
                message = f"""
Security Alert: Failed login attempt detected on your account.

Details:
- Time: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}
- IP Address: {ip_address}
- Attempts remaining: {attempts_left}

If this wasn't you, please contact support immediately.
                """.strip()
                
                create_security_notification(user, 'failed_login', ip_address, message)
    
    except User.DoesNotExist:
        pass
    
    return False

def generate_tfa_code(user, ip_address, session_key):
    """Generate and send 2FA code"""
    # Invalidate any existing unused codes for this user
    TwoFactorCode.objects.filter(user=user, used=False).update(used=True)
    
    # Create new 2FA code
    tfa_code = TwoFactorCode.objects.create(
        user=user,
        ip_address=ip_address,
        session_key=session_key
    )
    
    # Send code via email
    message = f"""
Your verification code for Kiharu Bursary System:

{tfa_code.code}

This code will expire in 2 minutes at {tfa_code.expires_at.strftime('%H:%M:%S')}.

Time: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}
IP Address: {ip_address}

If you didn't request this code, please contact support immediately.
    """.strip()
    
    create_security_notification(user, 'tfa_code', ip_address, message)
    
    return tfa_code

# Authentication Views
def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        tfa_code = request.POST.get('tfa_code', '').strip()
        
        ip_address = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Check if account is locked
        is_locked, account_lock, user_obj = check_account_lock(username, ip_address)
        if is_locked:
            messages.error(request, 'Account is temporarily locked due to multiple failed attempts. Please try again later.')
            return render(request, 'auth/login.html')
        
        # If 2FA code is provided, verify it
        if tfa_code:
            return handle_tfa_verification(request, username, tfa_code, ip_address)
        
        # Regular authentication
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            # Log successful authentication
            LoginAttempt.objects.create(
                username=username,
                ip_address=ip_address,
                success=True,
                user_agent=user_agent
            )
            
            # Reset failed attempts on successful authentication
            if hasattr(user, 'account_lock'):
                account_lock = user.account_lock
                account_lock.failed_attempts = 0
                account_lock.is_locked = False
                account_lock.unlock_time = None
                account_lock.save()
            
            if user.user_type in ['admin', 'reviewer', 'finance']:
                # Require 2FA for admin users
                session_key = get_session_key(request)  # Fixed: Ensure session exists
                tfa_code_obj = generate_tfa_code(user, ip_address, session_key)
                
                # Store pending login data in session
                request.session['pending_login_user_id'] = user.id
                request.session['pending_login_time'] = timezone.now().isoformat()
                request.session['tfa_code_id'] = tfa_code_obj.id
                
                messages.info(request, 'Verification code sent to your email. Please check and enter the code.')
                return render(request, 'auth/login.html', {
                    'show_tfa': True,
                    'username': username,
                    'expires_at': tfa_code_obj.expires_at.isoformat(),
                })
            
            elif user.user_type == 'applicant':
                # Direct login for applicants
                login(request, user)
                return redirect('student_dashboard')
        else:
            # Handle failed login
            was_locked = handle_failed_login(username, ip_address, user_agent)
            if was_locked:
                messages.error(request, 'Account locked due to multiple failed attempts. Check your email for details.')
            else:
                messages.error(request, 'Invalid credentials or insufficient permissions')
    
    return render(request, 'auth/login.html')

def handle_tfa_verification(request, username, tfa_code, ip_address):
    """Handle 2FA code verification"""
    try:
        # Get pending login data from session
        pending_user_id = request.session.get('pending_login_user_id')
        tfa_code_id = request.session.get('tfa_code_id')
        
        if not pending_user_id or not tfa_code_id:
            messages.error(request, 'Session expired. Please login again.')
            return redirect('login_view')
        
        user = get_object_or_404(User, id=pending_user_id, username=username)
        code_obj = get_object_or_404(TwoFactorCode, id=tfa_code_id, user=user)
        
        # Check if code is valid
        if not code_obj.is_valid():
            messages.error(request, 'Verification code has expired or already been used.')
            return render(request, 'auth/login.html', {
                'show_tfa': True,
                'username': username,
                'code_expired': True,
            })
        
        # Verify the code
        if code_obj.code == tfa_code:
            # Mark code as used
            code_obj.mark_as_used()
            
            # Clear session data
            request.session.pop('pending_login_user_id', None)
            request.session.pop('pending_login_time', None)
            request.session.pop('tfa_code_id', None)
            
            # Log the user in
            login(request, user)
            
            # Send successful login notification
            message = f"""
Successful login to your account:

Time: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}
IP Address: {ip_address}
User Type: {user.get_user_type_display()}

If this wasn't you, please contact support immediately.
            """.strip()
            
            create_security_notification(user, 'successful_login', ip_address, message)
            
            # Redirect based on user type
            if user.user_type == 'admin':
                return redirect('admin_dashboard')
            elif user.user_type == 'reviewer':
                return redirect('reviewer_dashboard')
            elif user.user_type == 'finance':
                return redirect('finance_dashboard')
        else:
            messages.error(request, 'Invalid verification code.')
            return render(request, 'auth/login.html', {
                'show_tfa': True,
                'username': username,
                'expires_at': code_obj.expires_at.isoformat(),
            })
    
    except Exception as e:
        logger.error(f"2FA verification error: {str(e)}")
        messages.error(request, 'An error occurred during verification. Please try again.')
        return redirect('login_view')

def resend_tfa_code(request):
    """Resend 2FA code via AJAX"""
    if request.method == 'POST':
        try:
            username = request.POST.get('username')
            pending_user_id = request.session.get('pending_login_user_id')
            
            if not pending_user_id:
                return JsonResponse({'success': False, 'message': 'Session expired'})
            
            user = get_object_or_404(User, id=pending_user_id, username=username)
            ip_address = get_client_ip(request)
            
            # Generate new code
            session_key = get_session_key(request)  # Fixed: Ensure session exists
            tfa_code_obj = generate_tfa_code(user, ip_address, session_key)
            request.session['tfa_code_id'] = tfa_code_obj.id
            
            return JsonResponse({
                'success': True,
                'message': 'New verification code sent to your email.',
                'expires_at': tfa_code_obj.expires_at.isoformat(),
            })
        
        except Exception as e:
            logger.error(f"Resend 2FA code error: {str(e)}")
            return JsonResponse({'success': False, 'message': 'Failed to send code'})
    
    return JsonResponse({'success': False, 'message': 'Invalid request'})

def logout_view(request):
    """Logout user and clear session"""
    # Clear any pending login data
    request.session.pop('pending_login_user_id', None)
    request.session.pop('pending_login_time', None)
    request.session.pop('tfa_code_id', None)
    
    logout(request)
    messages.success(request, 'You have been logged out successfully.')
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
from django.shortcuts import render
from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.paginator import Paginator
from django.db.models import Q, Count, Sum, Avg
from django.db.models.functions import Coalesce
from django.utils import timezone
from datetime import datetime, timedelta
from .models import Application, Ward, Institution, FiscalYear, BursaryCategory
from django.db.models import Sum, Avg, Q, DecimalField, Value
from django.db.models.functions import Coalesce

@login_required
@user_passes_test(is_reviewer)
def application_list(request):
    # Base queryset with optimized queries
    applications = Application.objects.select_related(
        'applicant__user', 
        'applicant__ward', 
        'institution', 
        'bursary_category',
        'fiscal_year'
    ).prefetch_related('reviews', 'allocation')
    
    # Search functionality
    search_query = request.GET.get('search', '').strip()
    if search_query:
        applications = applications.filter(
            Q(application_number__icontains=search_query) |
            Q(applicant__user__first_name__icontains=search_query) |
            Q(applicant__user__last_name__icontains=search_query) |
            Q(applicant__user__email__icontains=search_query) |
            Q(institution__name__icontains=search_query) |
            Q(applicant__id_number__icontains=search_query)
        )
    
    # Filtering
    status = request.GET.get('status')
    ward = request.GET.get('ward')
    institution_type = request.GET.get('institution_type')
    fiscal_year_id = request.GET.get('fiscal_year')
    date_from = request.GET.get('date_from')
    date_to = request.GET.get('date_to')
    amount_min = request.GET.get('amount_min')
    amount_max = request.GET.get('amount_max')
    
    # Apply filters
    if status:
        applications = applications.filter(status=status)
    if ward:
        applications = applications.filter(applicant__ward__id=ward)
    if institution_type:
        applications = applications.filter(bursary_category__category_type=institution_type)
    if fiscal_year_id:
        applications = applications.filter(fiscal_year__id=fiscal_year_id)
    
    # Date range filtering
    if date_from:
        try:
            from_date = datetime.strptime(date_from, '%Y-%m-%d').date()
            applications = applications.filter(date_submitted__date__gte=from_date)
        except ValueError:
            pass
    
    if date_to:
        try:
            to_date = datetime.strptime(date_to, '%Y-%m-%d').date()
            applications = applications.filter(date_submitted__date__lte=to_date)
        except ValueError:
            pass
    
    # Amount range filtering
    if amount_min:
        try:
            min_amount = float(amount_min)
            applications = applications.filter(amount_requested__gte=min_amount)
        except ValueError:
            pass
    
    if amount_max:
        try:
            max_amount = float(amount_max)
            applications = applications.filter(amount_requested__lte=max_amount)
        except ValueError:
            pass
    
    # Sorting
    sort_by = request.GET.get('sort', '-date_submitted')
    valid_sort_fields = [
        'date_submitted', '-date_submitted',
        'amount_requested', '-amount_requested',
        'applicant__user__last_name', '-applicant__user__last_name',
        'status', '-status',
        'application_number', '-application_number'
    ]
    
    if sort_by in valid_sort_fields:
        applications = applications.order_by(sort_by)
    else:
        applications = applications.order_by('-date_submitted')
    
    # Calculate statistics for all applications (without pagination)
    all_applications = Application.objects.all()
    
    # Status counts
    status_stats = all_applications.values('status').annotate(count=Count('id')).order_by('status')
    status_counts = {stat['status']: stat['count'] for stat in status_stats}
    
    # Financial statistics
    financial_stats = all_applications.aggregate(
        total_requested=Coalesce(Sum('amount_requested'), Value(0), output_field=DecimalField()),
        total_allocated=Coalesce(Sum('allocation__amount_allocated'), Value(0), output_field=DecimalField()),
        avg_requested=Coalesce(Avg('amount_requested'), Value(0), output_field=DecimalField()),
        total_disbursed=Coalesce(
            Sum('allocation__amount_allocated', filter=Q(allocation__is_disbursed=True)),
            Value(0),
            output_field=DecimalField()
        )
    )
    
    # Recent applications (last 30 days)
    thirty_days_ago = timezone.now() - timedelta(days=30)
    recent_count = all_applications.filter(date_submitted__gte=thirty_days_ago).count()
    
    # Ward-wise statistics
    ward_stats = all_applications.values(
        'applicant__ward__name'
    ).annotate(
        count=Count('id'),
        total_requested=Coalesce(Sum('amount_requested'), 0)
    ).order_by('-count')[:5]  # Top 5 wards
    
    # Institution type statistics
    institution_stats = all_applications.values(
        'bursary_category__category_type'
    ).annotate(
        count=Count('id'),
        total_requested=Coalesce(Sum('amount_requested'), 0)
    ).order_by('-count')
    
    # Pagination
    per_page = request.GET.get('per_page', 25)
    try:
        per_page = min(int(per_page), 100)  # Max 100 items per page
    except (ValueError, TypeError):
        per_page = 25
    
    paginator = Paginator(applications, per_page)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Filter options
    wards = Ward.objects.all().order_by('name')
    fiscal_years = FiscalYear.objects.all().order_by('-start_date')
    
    # Institution types for filter
    institution_types = [
        ('highschool', 'High School'),
        ('special_school', 'Special School'),
        ('college', 'College'),
        ('university', 'University'),
    ]
    
    # Application statuses for filter
    application_statuses = [
        ('draft', 'Draft'),
        ('submitted', 'Submitted'),
        ('under_review', 'Under Review'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('disbursed', 'Disbursed'),
    ]
    
    context = {
        'page_obj': page_obj,
        'applications': page_obj.object_list,
        'wards': wards,
        'fiscal_years': fiscal_years,
        'institution_types': institution_types,
        'application_statuses': application_statuses,
        
        # Current filter values
        'current_search': search_query,
        'current_status': status,
        'current_ward': ward,
        'current_institution_type': institution_type,
        'current_fiscal_year': fiscal_year_id,
        'current_date_from': date_from,
        'current_date_to': date_to,
        'current_amount_min': amount_min,
        'current_amount_max': amount_max,
        'current_sort': sort_by,
        'current_per_page': per_page,
        
        # Statistics
        'status_counts': status_counts,
        'financial_stats': financial_stats,
        'recent_count': recent_count,
        'ward_stats': ward_stats,
        'institution_stats': institution_stats,
        
        # Individual status counts for cards
        'draft_count': status_counts.get('draft', 0),
        'submitted_count': status_counts.get('submitted', 0),
        'under_review_count': status_counts.get('under_review', 0),
        'approved_count': status_counts.get('approved', 0),
        'rejected_count': status_counts.get('rejected', 0),
        'disbursed_count': status_counts.get('disbursed', 0),
        
        # Total applications count
        'total_applications': all_applications.count(),
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


# Add this to your Django views.py file

from django.http import HttpResponse, Http404, FileResponse
from django.shortcuts import get_object_or_404
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.conf import settings
import os
import mimetypes
from django.urls import reverse


@login_required
@require_http_methods(["GET"])
def serve_pdf_document(request, application_id, document_id):
    """
    Serve PDF documents with proper headers for iframe embedding
    """
    try:
        # Get the application and document (adjust based on your models)
        application = get_object_or_404(Application, id=application_id)
        document = get_object_or_404(Document, id=document_id, application=application)
        
        # Security check - ensure user has permission to view this document
        if not request.user.has_perm('view_application', application):
            raise Http404("Document not found")
        
        # Get the file path
        file_path = document.file.path
        
        if not os.path.exists(file_path):
            raise Http404("File not found")
        
        # Determine content type
        content_type, _ = mimetypes.guess_type(file_path)
        if not content_type:
            content_type = 'application/octet-stream'
        
        # Open and serve the file
        response = FileResponse(
            open(file_path, 'rb'),
            content_type=content_type
        )
        
        # Set headers to allow iframe embedding
        response['X-Frame-Options'] = 'SAMEORIGIN'
        response['Content-Security-Policy'] = "frame-ancestors 'self'"
        
        # For PDF files, set additional headers
        if content_type == 'application/pdf':
            response['Content-Disposition'] = f'inline; filename="{document.get_document_type_display()}.pdf"'
            # Allow PDF to be embedded in iframe
            response['X-Content-Type-Options'] = 'nosniff'
        
        return response
        
    except Exception as e:
        raise Http404(f"Error serving document: {str(e)}")


@login_required
def pdf_viewer(request, application_id, document_id):
    """
    Custom PDF viewer page that embeds PDF.js
    """
    try:
        application = get_object_or_404(Application, id=application_id)
        document = get_object_or_404(Document, id=document_id, application=application)
        
        # Security check
        if not request.user.has_perm('view_application', application):
            raise Http404("Document not found")
        
        # Generate the secure document URL
        document_url = request.build_absolute_uri(
            reverse('serve_pdf_document', args=[application_id, document_id])
        )
        
        context = {
            'document': document,
            'document_url': document_url,
            'application': application,
        }
        
        return render(request, 'admin/pdf_viewer.html', context)
        
    except Exception as e:
        raise Http404(f"Error loading PDF viewer: {str(e)}")


# Alternative: Simple document proxy for any file type
@login_required
def document_proxy(request, application_id, document_id):
    """
    Proxy for serving any document type with CORS headers
    """
    try:
        application = get_object_or_404(Application, id=application_id)
        document = get_object_or_404(Document, id=document_id, application=application)
        
        # Security check
        if not request.user.has_perm('view_application', application):
            return HttpResponse("Unauthorized", status=403)
        
        file_path = document.file.path
        
        if not os.path.exists(file_path):
            return HttpResponse("File not found", status=404)
        
        # Determine content type
        content_type, _ = mimetypes.guess_type(file_path)
        if not content_type:
            content_type = 'application/octet-stream'
        
        # Read file content
        with open(file_path, 'rb') as f:
            file_content = f.read()
        
        response = HttpResponse(file_content, content_type=content_type)
        
        # CORS headers
        response['Access-Control-Allow-Origin'] = request.get_host()
        response['Access-Control-Allow-Methods'] = 'GET'
        response['Access-Control-Allow-Headers'] = 'Content-Type'
        
        # Frame options
        response['X-Frame-Options'] = 'SAMEORIGIN'
        response['Content-Security-Policy'] = "frame-ancestors 'self'"
        
        # Cache control
        response['Cache-Control'] = 'private, max-age=3600'
        
        return response
        
    except Exception as e:
        return HttpResponse(f"Error: {str(e)}", status=500)
    
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

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.http import JsonResponse
from django.db.models import Count, Sum, Q
from django.core.paginator import Paginator
from django.utils import timezone
from datetime import datetime
import json
from .models import (
    FiscalYear, BursaryCategory, Application, Applicant, 
    Allocation, Ward, User
)

# Helper function to check if user is admin
def is_admin(user):
    return user.user_type == 'admin'

# Budget and Allocation Views
@login_required
@user_passes_test(is_admin)
def fiscal_year_list(request):
    fiscal_years = FiscalYear.objects.all().order_by('-start_date')
    
    # Add pagination
    paginator = Paginator(fiscal_years, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'fiscal_years': page_obj,
        'page_obj': page_obj
    }
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
        
        # Validate dates
        try:
            start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date()
            
            if start_date_obj >= end_date_obj:
                messages.error(request, 'End date must be after start date')
                return render(request, 'admin/fiscal_year_create.html')
        except ValueError:
            messages.error(request, 'Invalid date format')
            return render(request, 'admin/fiscal_year_create.html')
        
        # Check for overlapping fiscal years
        overlapping = FiscalYear.objects.filter(
            Q(start_date__lte=end_date_obj, end_date__gte=start_date_obj)
        ).exists()
        
        if overlapping:
            messages.error(request, 'Fiscal year dates overlap with existing fiscal year')
            return render(request, 'admin/fiscal_year_create.html')
        
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
        
        messages.success(request, f'Fiscal year {name} created successfully')
        return redirect('fiscal_year_list')
    
    return render(request, 'admin/fiscal_year_create.html')

from django.db.models.functions import TruncMonth
from django.core.serializers.json import DjangoJSONEncoder
import json

@login_required
@user_passes_test(is_admin)
def fiscal_year_detail(request, pk):
    fiscal_year = get_object_or_404(FiscalYear, pk=pk)
    categories = BursaryCategory.objects.filter(fiscal_year=fiscal_year)
    
    # Statistics
    total_applications = Application.objects.filter(fiscal_year=fiscal_year).count()
    approved_applications = Application.objects.filter(
        fiscal_year=fiscal_year, 
        status='approved'
    ).count()
    disbursed_applications = Application.objects.filter(
        fiscal_year=fiscal_year, 
        status='disbursed'
    ).count()
    
    # Total allocated amount
    total_allocated = Allocation.objects.filter(
        application__fiscal_year=fiscal_year
    ).aggregate(total=Sum('amount_allocated'))['total'] or 0
    
    # Remaining balance calculation
    remaining_balance = fiscal_year.total_allocation - total_allocated
    
    # Gender statistics
    gender_stats = Application.objects.filter(
        fiscal_year=fiscal_year
    ).values('applicant__gender').annotate(
        count=Count('id')
    )
    
    # Ward statistics
    ward_stats = Application.objects.filter(
        fiscal_year=fiscal_year
    ).values('applicant__ward__name').annotate(
        count=Count('id')
    ).order_by('-count')[:10]  # Top 10 wards
    
    # Category statistics
    category_stats = Application.objects.filter(
        fiscal_year=fiscal_year
    ).values('bursary_category__name').annotate(
        count=Count('id'),
        allocated=Sum('allocation__amount_allocated')
    )
    
    # Monthly application trends with proper date formatting
    monthly_stats_raw = (
        Application.objects.filter(fiscal_year=fiscal_year)
        .annotate(month=TruncMonth('date_submitted'))
        .values('month')
        .annotate(count=Count('id'))
        .order_by('month')
    )
    
    # Format monthly stats for JavaScript consumption
    monthly_stats = []
    for stat in monthly_stats_raw:
        if stat['month']:  # Check if month is not None
            # Format the date as "YYYY-MM" or "MMM YYYY" for better display
            month_str = stat['month'].strftime('%b %Y')
            monthly_stats.append({
                'month': month_str,
                'count': stat['count']
            })
    
    # Calculate utilization rate
    utilization_rate = (total_allocated / fiscal_year.total_allocation * 100) if fiscal_year.total_allocation > 0 else 0
    
    context = {
        'fiscal_year': fiscal_year,
        'categories': categories,
        'total_applications': total_applications,
        'approved_applications': approved_applications,
        'disbursed_applications': disbursed_applications,
        'total_allocated': total_allocated,
        'remaining_balance': remaining_balance,
        'utilization_rate': utilization_rate,
        # Convert to JSON strings for safe template rendering
        'gender_stats': json.dumps(list(gender_stats), cls=DjangoJSONEncoder),
        'ward_stats': json.dumps(list(ward_stats), cls=DjangoJSONEncoder),
        'category_stats': json.dumps(list(category_stats), cls=DjangoJSONEncoder),
        'monthly_stats': json.dumps(monthly_stats, cls=DjangoJSONEncoder),
    }
    
    return render(request, 'admin/fiscal_year_detail.html', context)

@login_required
@user_passes_test(is_admin)
def fiscal_year_update(request, pk):
    fiscal_year = get_object_or_404(FiscalYear, pk=pk)
    
    if request.method == 'POST':
        name = request.POST['name']
        start_date = request.POST['start_date']
        end_date = request.POST['end_date']
        total_allocation = request.POST['total_allocation']
        is_active = 'is_active' in request.POST
        
        # Validate dates
        try:
            start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date()
            
            if start_date_obj >= end_date_obj:
                messages.error(request, 'End date must be after start date')
                context = {'fiscal_year': fiscal_year}
                return render(request, 'admin/fiscal_year_update.html', context)
        except ValueError:
            messages.error(request, 'Invalid date format')
            context = {'fiscal_year': fiscal_year}
            return render(request, 'admin/fiscal_year_update.html', context)
        
        # Check for overlapping fiscal years (excluding current one)
        overlapping = FiscalYear.objects.filter(
            Q(start_date__lte=end_date_obj, end_date__gte=start_date_obj)
        ).exclude(pk=pk).exists()
        
        if overlapping:
            messages.error(request, 'Fiscal year dates overlap with existing fiscal year')
            context = {'fiscal_year': fiscal_year}
            return render(request, 'admin/fiscal_year_update.html', context)
        
        # Deactivate other fiscal years if this one is active
        if is_active and not fiscal_year.is_active:
            FiscalYear.objects.exclude(pk=pk).update(is_active=False)
        
        # Update fiscal year
        fiscal_year.name = name
        fiscal_year.start_date = start_date
        fiscal_year.end_date = end_date
        fiscal_year.total_allocation = total_allocation
        fiscal_year.is_active = is_active
        fiscal_year.save()
        
        messages.success(request, f'Fiscal year {name} updated successfully')
        return redirect('fiscal_year_detail', pk=pk)
    
    context = {'fiscal_year': fiscal_year}
    return render(request, 'admin/fiscal_year_update.html', context)

@login_required
@user_passes_test(is_admin)
def fiscal_year_delete(request, pk):
    fiscal_year = get_object_or_404(FiscalYear, pk=pk)
    
    # Check if there are applications linked to this fiscal year
    application_count = Application.objects.filter(fiscal_year=fiscal_year).count()
    
    if request.method == 'POST':
        if application_count > 0:
            messages.error(request, 'Cannot delete fiscal year with existing applications')
            return redirect('fiscal_year_detail', pk=pk)
        
        fiscal_year_name = fiscal_year.name
        fiscal_year.delete()
        messages.success(request, f'Fiscal year {fiscal_year_name} deleted successfully')
        return redirect('fiscal_year_list')
    
    context = {
        'fiscal_year': fiscal_year,
        'application_count': application_count
    }
    return render(request, 'admin/fiscal_year_delete.html', context)


from django.db.models.functions import TruncMonth
from django.core.serializers.json import DjangoJSONEncoder
import json

@login_required
@user_passes_test(is_admin)
def fiscal_year_analytics(request, pk):
    fiscal_year = get_object_or_404(FiscalYear, pk=pk)
    
    # Comprehensive analytics data
    applications = Application.objects.filter(fiscal_year=fiscal_year)
    
    # Gender distribution
    gender_data = applications.values('applicant__gender').annotate(
        count=Count('id')
    )
    
    # Ward distribution (top 10)
    ward_data = applications.values('applicant__ward__name').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    # Institution type distribution
    institution_data = applications.values('institution__institution_type').annotate(
        count=Count('id')
    )
    
    # Status distribution
    status_data = applications.values('status').annotate(
        count=Count('id')
    )
    
    # Monthly submission trends - using TruncMonth for database compatibility
    monthly_data_raw = applications.annotate(
        month=TruncMonth('date_submitted')
    ).values('month').annotate(
        count=Count('id')
    ).order_by('month')
    
    # Format monthly data for JavaScript consumption
    monthly_data = []
    for data in monthly_data_raw:
        if data['month']:  # Check if month is not None
            month_str = data['month'].strftime('%Y-%m')
            month_display = data['month'].strftime('%b %Y')
            monthly_data.append({
                'month': month_display,
                'month_key': month_str,
                'count': data['count']
            })
    
    # Amount requested vs allocated by category
    category_financial_data = applications.values(
        'bursary_category__name'
    ).annotate(
        total_requested=Sum('amount_requested'),
        total_allocated=Sum('allocation__amount_allocated'),
        count=Count('id')
    )
    
    # Age distribution
    current_year = timezone.now().year
    age_groups = [
        {'label': '15-18', 'min_age': 15, 'max_age': 18},
        {'label': '19-22', 'min_age': 19, 'max_age': 22},
        {'label': '23-26', 'min_age': 23, 'max_age': 26},
        {'label': '27+', 'min_age': 27, 'max_age': 100},
    ]
    
    age_data = []
    for group in age_groups:
        # Calculate birth year range
        max_birth_year = current_year - group['min_age']
        min_birth_year = current_year - group['max_age']
        
        count = applications.filter(
            applicant__date_of_birth__year__lte=max_birth_year,
            applicant__date_of_birth__year__gte=min_birth_year
        ).count()
        age_data.append({'label': group['label'], 'count': count})
    
    # Special needs statistics
    special_needs_data = applications.values('applicant__special_needs').annotate(
        count=Count('id')
    )
    
    # Orphan statistics
    orphan_data = applications.values('is_orphan').annotate(
        count=Count('id')
    )
    
    # Calculate totals
    total_applications = applications.count()
    total_amount_requested = applications.aggregate(
        total=Sum('amount_requested')
    )['total'] or 0
    total_amount_allocated = Allocation.objects.filter(
        application__fiscal_year=fiscal_year
    ).aggregate(total=Sum('amount_allocated'))['total'] or 0
    
    # Calculate allocation rate
    allocation_rate = 0
    if total_amount_requested > 0:
        allocation_rate = (total_amount_allocated / total_amount_requested) * 100
    
    context = {
        'fiscal_year': fiscal_year,
        'gender_data': json.dumps(list(gender_data), cls=DjangoJSONEncoder),
        'ward_data': json.dumps(list(ward_data), cls=DjangoJSONEncoder),
        'institution_data': json.dumps(list(institution_data), cls=DjangoJSONEncoder),
        'status_data': json.dumps(list(status_data), cls=DjangoJSONEncoder),
        'monthly_data': json.dumps(monthly_data, cls=DjangoJSONEncoder),
        'category_financial_data': json.dumps(list(category_financial_data), cls=DjangoJSONEncoder),
        'age_data': json.dumps(age_data, cls=DjangoJSONEncoder),
        'special_needs_data': json.dumps(list(special_needs_data), cls=DjangoJSONEncoder),
        'orphan_data': json.dumps(list(orphan_data), cls=DjangoJSONEncoder),
        'total_applications': total_applications,
        'total_amount_requested': total_amount_requested,
        'total_amount_allocated': total_amount_allocated,
        'allocation_rate': allocation_rate,  # Pre-calculated allocation rate
    }
    
    return render(request, 'admin/fiscal_year_analytics.html', context)

@login_required
@user_passes_test(is_admin)
def fiscal_year_toggle_active(request, pk):
    """AJAX view to toggle fiscal year active status"""
    if request.method == 'POST':
        fiscal_year = get_object_or_404(FiscalYear, pk=pk)
        
        if not fiscal_year.is_active:
            # Deactivate all other fiscal years
            FiscalYear.objects.exclude(pk=pk).update(is_active=False)
            fiscal_year.is_active = True
        else:
            fiscal_year.is_active = False
        
        fiscal_year.save()
        
        return JsonResponse({
            'success': True,
            'is_active': fiscal_year.is_active,
            'message': f'Fiscal year {fiscal_year.name} {"activated" if fiscal_year.is_active else "deactivated"}'
        })
    
    return JsonResponse({'success': False})

# Bursary Category Views
@login_required
@user_passes_test(is_admin)
def bursary_category_list(request):
    # Get fiscal year filter from GET parameter
    fiscal_year_id = request.GET.get('fiscal_year')
    
    # Base queryset
    categories = BursaryCategory.objects.all().select_related('fiscal_year').order_by('-fiscal_year__start_date', 'name')
    
    # Filter by fiscal year if provided
    selected_fiscal_year = None
    if fiscal_year_id:
        try:
            selected_fiscal_year = FiscalYear.objects.get(pk=fiscal_year_id)
            categories = categories.filter(fiscal_year=selected_fiscal_year)
        except FiscalYear.DoesNotExist:
            messages.warning(request, 'Selected fiscal year not found')
    
    # Get all fiscal years for the filter dropdown
    all_fiscal_years = FiscalYear.objects.all().order_by('-start_date')
    
    # Add pagination
    paginator = Paginator(categories, 15)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Calculate statistics for the filtered results
    if selected_fiscal_year:
        # Statistics for selected fiscal year
        total_applications = Application.objects.filter(
            fiscal_year=selected_fiscal_year
        ).count()
        
        total_allocated = categories.aggregate(
            total=Sum('allocation_amount')
        )['total'] or 0
        
        utilization = Allocation.objects.filter(
            application__fiscal_year=selected_fiscal_year
        ).aggregate(total=Sum('amount_allocated'))['total'] or 0
        
        utilization_rate = (utilization / total_allocated * 100) if total_allocated > 0 else 0
        
        stats = {
            'total_categories': categories.count(),
            'total_allocation': total_allocated,
            'total_utilized': utilization,
            'utilization_rate': utilization_rate,
            'total_applications': total_applications,
        }
    else:
        stats = None
    
    context = {
        'categories': page_obj,
        'page_obj': page_obj,
        'all_fiscal_years': all_fiscal_years,
        'selected_fiscal_year': selected_fiscal_year,
        'stats': stats,
    }
    return render(request, 'admin/bursary_category_list.html', context)

@login_required
@user_passes_test(is_admin)
def bursary_category_create(request):
    # Get fiscal year from GET parameter if provided (for pre-selection)
    fiscal_year_id = request.GET.get('fiscal_year')
    selected_fiscal_year = None
    
    if fiscal_year_id:
        try:
            selected_fiscal_year = FiscalYear.objects.get(pk=fiscal_year_id)
        except FiscalYear.DoesNotExist:
            pass
    
    if request.method == 'POST':
        name = request.POST['name']
        category_type = request.POST['category_type']
        fiscal_year_id = request.POST['fiscal_year']
        allocation_amount = request.POST['allocation_amount']
        max_amount_per_applicant = request.POST['max_amount_per_applicant']
        
        fiscal_year = get_object_or_404(FiscalYear, pk=fiscal_year_id)
        
        # Validate that max amount per applicant is not greater than allocation amount
        if float(max_amount_per_applicant) > float(allocation_amount):
            messages.error(request, 'Maximum amount per applicant cannot exceed total allocation')
            context = {
                'fiscal_years': FiscalYear.objects.all().order_by('-start_date'),
                'selected_fiscal_year': selected_fiscal_year
            }
            return render(request, 'admin/bursary_category_create.html', context)
        
        # Check if total allocation doesn't exceed fiscal year allocation
        existing_allocation = BursaryCategory.objects.filter(
            fiscal_year=fiscal_year
        ).aggregate(total=Sum('allocation_amount'))['total'] or 0
        
        if existing_allocation + float(allocation_amount) > fiscal_year.total_allocation:
            messages.error(request, f'Total category allocation would exceed fiscal year allocation of KES {fiscal_year.total_allocation:,.2f}')
            context = {
                'fiscal_years': FiscalYear.objects.all().order_by('-start_date'),
                'selected_fiscal_year': selected_fiscal_year
            }
            return render(request, 'admin/bursary_category_create.html', context)
        
        category = BursaryCategory.objects.create(
            name=name,
            category_type=category_type,
            fiscal_year=fiscal_year,
            allocation_amount=allocation_amount,
            max_amount_per_applicant=max_amount_per_applicant
        )
        
        messages.success(request, f'Bursary category {name} created successfully')
        
        # Redirect back to filtered list if fiscal year was selected
        if fiscal_year_id:
            return redirect(f"{reverse('bursary_category_list')}?fiscal_year={fiscal_year_id}")
        return redirect('bursary_category_list')
    
    context = {
        'fiscal_years': FiscalYear.objects.all().order_by('-start_date'),
        'selected_fiscal_year': selected_fiscal_year
    }
    return render(request, 'admin/bursary_category_create.html', context)

@login_required
@user_passes_test(is_admin)
def bursary_category_update(request, pk):
    category = get_object_or_404(BursaryCategory, pk=pk)
    if request.method == 'POST':
        form = BursaryCategoryForm(request.POST, instance=category)
        if form.is_valid():
            form.save()
            messages.success(request, "Bursary category updated successfully.")
            return redirect('bursary_category_list')  # adjust this to your list view
    else:
        form = BursaryCategoryForm(instance=category)
    return render(request, 'admin/bursary_category_form.html', {'form': form, 'title': 'Update Bursary Category'})

@login_required
@user_passes_test(is_admin)
def bursary_category_detail(request, pk):
    category = get_object_or_404(BursaryCategory, pk=pk)
    applications = Application.objects.filter(bursary_category=category)
    
    # Statistics
    total_applications = applications.count()
    approved_applications = applications.filter(status='approved').count()
    total_allocated = Allocation.objects.filter(
        application__bursary_category=category
    ).aggregate(total=Sum('amount_allocated'))['total'] or 0
    
    # Remaining allocation
    remaining_allocation = category.allocation_amount - total_allocated
    
    context = {
        'category': category,
        'total_applications': total_applications,
        'approved_applications': approved_applications,
        'total_allocated': total_allocated,
        'remaining_allocation': remaining_allocation,
        'utilization_rate': (total_allocated / category.allocation_amount * 100) if category.allocation_amount > 0 else 0
    }
    
    return render(request, 'admin/bursary_category_detail.html', context)


from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import ListView
from django.http import HttpResponse
from django.template.loader import render_to_string
from django.db.models import Q, Sum, Count
from weasyprint import HTML
import tempfile
import os
from datetime import datetime

from .models import (
    BursaryCategory, Application, Applicant, 
    User, FiscalYear, Institution, Ward
)


class BursaryCategoryApplicationsView(LoginRequiredMixin, ListView):
    """
    View to display all applications for a specific bursary category
    """
    model = Application
    template_name = 'bursary/category_applications.html'
    context_object_name = 'applications'
    paginate_by = 20

    def get_queryset(self):
        self.category = get_object_or_404(BursaryCategory, pk=self.kwargs['category_id'])
        queryset = Application.objects.filter(
            bursary_category=self.category
        ).select_related(
            'applicant__user',
            'applicant__ward',
            'institution',
            'allocation'
        ).order_by('-date_submitted')
        
        # Filter by status if provided
        status = self.request.GET.get('status')
        if status:
            queryset = queryset.filter(status=status)
        
        # Filter by ward if provided
        ward = self.request.GET.get('ward')
        if ward:
            queryset = queryset.filter(applicant__ward_id=ward)
        
        # Search functionality
        search = self.request.GET.get('search')
        if search:
            queryset = queryset.filter(
                Q(applicant__user__first_name__icontains=search) |
                Q(applicant__user__last_name__icontains=search) |
                Q(application_number__icontains=search) |
                Q(applicant__id_number__icontains=search)
            )
        
        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['category'] = self.category

        # Summary statistics
        applications = self.get_queryset()
        context['total_applications'] = applications.count()
        context['total_requested'] = applications.aggregate(
            total=Sum('amount_requested')
        )['total'] or 0
        context['total_allocated'] = applications.filter(
            allocation__isnull=False
        ).aggregate(
            total=Sum('allocation__amount_allocated')
        )['total'] or 0

        # 👇 Add remaining allocation calculation
        context['remaining_amount'] = (
            self.category.allocation_amount - context['total_allocated']
        )

        # Status breakdown
        context['status_stats'] = dict(
            applications.values_list('status').annotate(
                count=Count('status')
            )
        )

        # Filter options
        context['wards'] = Ward.objects.all()
        context['status_choices'] = Application.APPLICATION_STATUS

        # Current filters
        context['current_filters'] = {
            'status': self.request.GET.get('status', ''),
            'ward': self.request.GET.get('ward', ''),
            'search': self.request.GET.get('search', ''),
        }

        return context

@login_required
def bursary_category_applications_pdf(request, category_id):
    """
    Generate PDF report of applications for a specific bursary category
    """
    category = get_object_or_404(BursaryCategory, pk=category_id)
    
    # Get applications with same filters as the list view
    applications = Application.objects.filter(
        bursary_category=category
    ).select_related(
        'applicant__user',
        'applicant__ward',
        'applicant__location',
        'institution',
        'allocation'
    ).order_by('applicant__ward__name', 'applicant__user__last_name')
    
    # Apply filters from GET parameters
    status = request.GET.get('status')
    if status:
        applications = applications.filter(status=status)
    
    ward = request.GET.get('ward')
    if ward:
        applications = applications.filter(applicant__ward_id=ward)
    
    search = request.GET.get('search')
    if search:
        applications = applications.filter(
            Q(applicant__user__first_name__icontains=search) |
            Q(applicant__user__last_name__icontains=search) |
            Q(application_number__icontains=search) |
            Q(applicant__id_number__icontains=search)
        )
    
    # Calculate summary statistics
    total_applications = applications.count()
    total_requested = applications.aggregate(
        total=Sum('amount_requested')
    )['total'] or 0
    total_allocated = applications.filter(
        allocation__isnull=False
    ).aggregate(
        total=Sum('allocation__amount_allocated')
    )['total'] or 0
    
    # Status breakdown
    status_stats = dict(
        applications.values_list('status').annotate(
            count=Count('status')
        )
    )
    
    # Group applications by ward for better organization
    ward_groups = {}
    for app in applications:
        ward_name = app.applicant.ward.name if app.applicant.ward else 'No Ward'
        if ward_name not in ward_groups:
            ward_groups[ward_name] = []
        ward_groups[ward_name].append(app)
    
    context = {
        'category': category,
        'applications': applications,
        'ward_groups': ward_groups,
        'total_applications': total_applications,
        'total_requested': total_requested,
        'total_allocated': total_allocated,
        'status_stats': status_stats,
        'generated_at': datetime.now(),
        'generated_by': request.user,
        'filters_applied': {
            'status': status,
            'ward': Ward.objects.get(pk=ward).name if ward else None,
            'search': search,
        }
    }
    
    # Render HTML template
    html_string = render_to_string('bursary/category_applications_pdf.html', context)
    
    # Generate PDF
    html = HTML(string=html_string)
    
    # Create response
    response = HttpResponse(content_type='application/pdf')
    filename = f"bursary_applications_{category.name.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    
    # Write PDF to response
    html.write_pdf(target=response)
    
    return response


@login_required
def bursary_category_summary_pdf(request, category_id):
    """
    Generate a summary PDF report for a bursary category
    """
    category = get_object_or_404(BursaryCategory, pk=category_id)
    
    applications = Application.objects.filter(bursary_category=category)
    
    # Summary statistics
    total_requested_result = applications.aggregate(total=Sum('amount_requested'))
    total_allocated_result = applications.filter(allocation__isnull=False).aggregate(total=Sum('allocation__amount_allocated'))
    
    total_requested = total_requested_result['total'] if total_requested_result['total'] is not None else 0
    total_allocated = total_allocated_result['total'] if total_allocated_result['total'] is not None else 0
    
    stats = {
        'total_applications': applications.count(),
        'submitted': applications.filter(status='submitted').count(),
        'under_review': applications.filter(status='under_review').count(),
        'approved': applications.filter(status='approved').count(),
        'rejected': applications.filter(status='rejected').count(),
        'disbursed': applications.filter(status='disbursed').count(),
        'total_requested': total_requested,
        'total_allocated': total_allocated,
        'allocation_remaining': category.allocation_amount - total_allocated
    }
    
    # Ward breakdown - handle potential None values
    ward_breakdown = applications.values(
        'applicant__ward__name'
    ).annotate(
        count=Count('id'),
        total_requested=Sum('amount_requested'),
        total_allocated=Sum('allocation__amount_allocated')
    ).order_by('applicant__ward__name')
    
    # Process ward breakdown to handle None values
    ward_breakdown_processed = []
    for ward in ward_breakdown:
        ward_breakdown_processed.append({
            'applicant__ward__name': ward['applicant__ward__name'],
            'count': ward['count'],
            'total_requested': ward['total_requested'] if ward['total_requested'] is not None else 0,
            'total_allocated': ward['total_allocated'] if ward['total_allocated'] is not None else 0,
        })
    
    # Institution breakdown - handle potential None values
    institution_breakdown = applications.values(
        'institution__name'
    ).annotate(
        count=Count('id'),
        total_requested=Sum('amount_requested'),
        total_allocated=Sum('allocation__amount_allocated')
    ).order_by('-count')[:10]  # Top 10 institutions
    
    # Process institution breakdown to handle None values
    institution_breakdown_processed = []
    for institution in institution_breakdown:
        institution_breakdown_processed.append({
            'institution__name': institution['institution__name'],
            'count': institution['count'],
            'total_requested': institution['total_requested'] if institution['total_requested'] is not None else 0,
            'total_allocated': institution['total_allocated'] if institution['total_allocated'] is not None else 0,
        })
    
    context = {
        'category': category,
        'stats': stats,
        'ward_breakdown': ward_breakdown_processed,
        'institution_breakdown': institution_breakdown_processed,
        'generated_at': datetime.now(),
        'generated_by': request.user,
    }
    
    html_string = render_to_string('bursary/category_summary_pdf.html', context)
    html = HTML(string=html_string)
    
    response = HttpResponse(content_type='application/pdf')
    filename = f"bursary_summary_{category.name.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    
    html.write_pdf(target=response)
    
    return response


@login_required
@user_passes_test(is_admin)
def allocation_list(request):
    allocations = Allocation.objects.all()\
    .select_related('application__applicant__user', 'approved_by')\
    .order_by('-allocation_date')

    
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
                return redirect('student_application_documents', pk=application.pk)
                
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
    
    # Define required document types
    required_documents = ['id_card', 'admission_letter', 'fee_structure', 'fee_statement']
    
    if request.method == 'POST':
        form = DocumentForm(request.POST, request.FILES)
        if form.is_valid():
            document = form.save(commit=False)
            document.application = application
            document.save()
            
            # Check if all required documents are uploaded
            uploaded_types = list(Document.objects.filter(
                application=application, 
                document_type__in=required_documents
            ).values_list('document_type', flat=True))
            
            completion_percentage = (len(uploaded_types) / len(required_documents)) * 100
            
            response_data = {
                'success': True,
                'message': 'Document uploaded successfully!',
                'uploaded_types': uploaded_types,
                'completion_percentage': completion_percentage,
                'all_required_uploaded': len(uploaded_types) == len(required_documents),
                'document_type': document.document_type,
                'document_name': document.get_document_type_display()
            }
            
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse(response_data)
            else:
                messages.success(request, 'Document uploaded successfully!')
                return redirect('student_application_documents', pk=pk)
    else:
        form = DocumentForm()
    
    documents = Document.objects.filter(application=application)
    
    # Get uploaded required document types
    uploaded_required_docs = list(documents.filter(
        document_type__in=required_documents
    ).values_list('document_type', flat=True))
    
    # Calculate completion percentage
    completion_percentage = (len(uploaded_required_docs) / len(required_documents)) * 100
    all_required_uploaded = len(uploaded_required_docs) == len(required_documents)
    
    context = {
        'application': application,
        'documents': documents,
        'form': form,
        'required_documents': required_documents,
        'uploaded_required_docs': uploaded_required_docs,
        'completion_percentage': completion_percentage,
        'all_required_uploaded': all_required_uploaded,
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



# views.py
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.contrib.auth import get_user_model
from django.contrib import messages
from django.db import transaction
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views.generic import View
from django.core.exceptions import ValidationError
from django.contrib.auth.decorators import login_required, user_passes_test
from django.utils import timezone
import json
import uuid
from decimal import Decimal

from .models import (
    User, Applicant, Application, Ward, Location, SubLocation, Village,
    Institution, FiscalYear, BursaryCategory, Guardian, SiblingInformation
)

def is_admin_or_reviewer(user):
    """Check if user is admin or reviewer"""
    return user.is_authenticated and user.user_type in ['admin', 'reviewer']

@method_decorator(login_required, name='dispatch')
@method_decorator(user_passes_test(is_admin_or_reviewer), name='dispatch')
class CreateApplicationView(View):
    template_name = 'applications/create_application.html'
    
    def get(self, request):
        """Display the application creation form"""
        context = self.get_context_data()
        return render(request, self.template_name, context)
    
    def post(self, request):
        """Handle form submission"""
        try:
            data = json.loads(request.body)
            action = data.get('action')
            
            if action == 'create_user':
                return self.create_user(request, data)
            elif action == 'search_user':
                return self.search_user(request, data)
            elif action == 'create_application':
                return self.create_application(request, data)
            elif action == 'get_locations':
                return self.get_locations(request, data)
            elif action == 'get_sublocations':
                return self.get_sublocations(request, data)
            elif action == 'get_villages':
                return self.get_villages(request, data)
            else:
                return JsonResponse({'success': False, 'message': 'Invalid action'})
                
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'message': 'Invalid JSON data'})
        except Exception as e:
            return JsonResponse({'success': False, 'message': str(e)})
    
    def get_context_data(self):
        """Get context data for the template"""
        return {
            'wards': Ward.objects.all().order_by('name'),
            'institutions': Institution.objects.all().order_by('name'),
            'fiscal_years': FiscalYear.objects.filter(is_active=True).order_by('-start_date'),
            'bursary_categories': BursaryCategory.objects.select_related('fiscal_year').order_by('name'),
            'user_types': User.USER_TYPES,
            'gender_choices': Applicant.GENDER_CHOICES,
            'relationship_choices': Guardian.RELATIONSHIP_CHOICES,
            'institution_types': Institution.INSTITUTION_TYPES,
        }
    
    def create_user(self, request, data):
        """Create a new user account"""
        try:
            with transaction.atomic():
                # Validate required fields
                required_fields = ['username', 'email', 'first_name', 'last_name', 'phone_number', 'id_number']
                for field in required_fields:
                    if not data.get(field, '').strip():
                        return JsonResponse({
                            'success': False, 
                            'message': f'{field.replace("_", " ").title()} is required'
                        })
                
                # Check if username or email already exists
                if User.objects.filter(username=data['username']).exists():
                    return JsonResponse({
                        'success': False, 
                        'message': 'Username already exists'
                    })
                
                if User.objects.filter(email=data['email']).exists():
                    return JsonResponse({
                        'success': False, 
                        'message': 'Email already exists'
                    })
                
                # Create user
                user = User.objects.create_user(
                    username=data['username'],
                    email=data['email'],
                    first_name=data['first_name'],
                    last_name=data['last_name'],
                    user_type='applicant',
                    phone_number=data['phone_number'],
                    id_number=data['id_number']
                )
                
                # Set password
                if data.get('password'):
                    user.set_password(data['password'])
                else:
                    # Generate random password
                    password = uuid.uuid4().hex[:12]
                    user.set_password(password)
                
                user.save()
                
                return JsonResponse({
                    'success': True,
                    'message': 'User created successfully',
                    'user': {
                        'id': user.id,
                        'username': user.username,
                        'full_name': f"{user.first_name} {user.last_name}",
                        'email': user.email,
                        'phone_number': user.phone_number,
                        'id_number': user.id_number
                    }
                })
                
        except ValidationError as e:
            return JsonResponse({
                'success': False,
                'message': str(e)
            })
        except Exception as e:
            return JsonResponse({
                'success': False,
                'message': f'Error creating user: {str(e)}'
            })
    
    def search_user(self, request, data):
        """Search for existing users"""
        query = data.get('query', '').strip()
        if not query:
            return JsonResponse({'success': False, 'message': 'Search query required'})
        
        users = User.objects.filter(
            user_type='applicant'
        ).filter(
            models.Q(username__icontains=query) |
            models.Q(first_name__icontains=query) |
            models.Q(last_name__icontains=query) |
            models.Q(email__icontains=query) |
            models.Q(id_number__icontains=query)
        )[:10]  # Limit results
        
        user_list = []
        for user in users:
            user_list.append({
                'id': user.id,
                'username': user.username,
                'full_name': f"{user.first_name} {user.last_name}",
                'email': user.email,
                'phone_number': user.phone_number,
                'id_number': user.id_number,
                'has_applicant_profile': hasattr(user, 'applicant_profile')
            })
        
        return JsonResponse({
            'success': True,
            'users': user_list
        })
    
    def create_application(self, request, data):
        """Create new application with applicant profile"""
        try:
            with transaction.atomic():
                user_id = data.get('user_id')
                if not user_id:
                    return JsonResponse({
                        'success': False,
                        'message': 'User ID is required'
                    })
                
                user = get_object_or_404(User, id=user_id)
                
                # Create or get applicant profile
                applicant_data = data.get('applicant', {})
                if hasattr(user, 'applicant_profile'):
                    applicant = user.applicant_profile
                    # Update existing applicant data
                    for field, value in applicant_data.items():
                        if field in ['ward_id', 'location_id', 'sublocation_id', 'village_id']:
                            if value:
                                related_field = field.replace('_id', '')
                                model_map = {
                                    'ward': Ward,
                                    'location': Location,
                                    'sublocation': SubLocation,
                                    'village': Village
                                }
                                setattr(applicant, related_field, model_map[related_field].objects.get(id=value))
                        else:
                            setattr(applicant, field, value)
                    applicant.save()
                else:
                    # Create new applicant profile
                    applicant = Applicant.objects.create(
                        user=user,
                        gender=applicant_data.get('gender'),
                        date_of_birth=applicant_data.get('date_of_birth'),
                        id_number=applicant_data.get('id_number', user.id_number),
                        ward_id=applicant_data.get('ward_id'),
                        location_id=applicant_data.get('location_id'),
                        sublocation_id=applicant_data.get('sublocation_id'),
                        village_id=applicant_data.get('village_id'),
                        physical_address=applicant_data.get('physical_address', ''),
                        postal_address=applicant_data.get('postal_address', ''),
                        special_needs=applicant_data.get('special_needs', False),
                        special_needs_description=applicant_data.get('special_needs_description', '')
                    )
                
                # Create guardians
                guardians_data = data.get('guardians', [])
                # Clear existing guardians
                applicant.guardians.all().delete()
                for guardian_data in guardians_data:
                    if guardian_data.get('name'):
                        Guardian.objects.create(
                            applicant=applicant,
                            name=guardian_data.get('name'),
                            relationship=guardian_data.get('relationship'),
                            phone_number=guardian_data.get('phone_number', ''),
                            email=guardian_data.get('email', ''),
                            occupation=guardian_data.get('occupation', ''),
                            monthly_income=guardian_data.get('monthly_income', 0),
                            id_number=guardian_data.get('id_number', '')
                        )
                
                # Create siblings
                siblings_data = data.get('siblings', [])
                # Clear existing siblings
                applicant.siblings.all().delete()
                for sibling_data in siblings_data:
                    if sibling_data.get('name'):
                        SiblingInformation.objects.create(
                            applicant=applicant,
                            name=sibling_data.get('name'),
                            age=sibling_data.get('age', 0),
                            education_level=sibling_data.get('education_level', ''),
                            school_name=sibling_data.get('school_name', '')
                        )
                
                # Create application
                application_data = data.get('application', {})
                fiscal_year = get_object_or_404(FiscalYear, id=application_data.get('fiscal_year_id'))
                bursary_category = get_object_or_404(BursaryCategory, id=application_data.get('bursary_category_id'))
                institution = get_object_or_404(Institution, id=application_data.get('institution_id'))
                
                application = Application.objects.create(
                    applicant=applicant,
                    fiscal_year=fiscal_year,
                    bursary_category=bursary_category,
                    institution=institution,
                    admission_number=application_data.get('admission_number'),
                    year_of_study=application_data.get('year_of_study'),
                    course_name=application_data.get('course_name', ''),
                    expected_completion_date=application_data.get('expected_completion_date'),
                    total_fees_payable=Decimal(str(application_data.get('total_fees_payable', '0'))),
                    fees_paid=Decimal(str(application_data.get('fees_paid', '0'))),
                    fees_balance=Decimal(str(application_data.get('fees_balance', '0'))),
                    amount_requested=Decimal(str(application_data.get('amount_requested', '0'))),
                    other_bursaries=application_data.get('other_bursaries', False),
                    other_bursaries_amount=Decimal(str(application_data.get('other_bursaries_amount', '0'))),
                    other_bursaries_source=application_data.get('other_bursaries_source', ''),
                    is_orphan=application_data.get('is_orphan', False),
                    is_disabled=application_data.get('is_disabled', False),
                    has_chronic_illness=application_data.get('has_chronic_illness', False),
                    chronic_illness_description=application_data.get('chronic_illness_description', ''),
                    previous_allocation=application_data.get('previous_allocation', False),
                    previous_allocation_year=application_data.get('previous_allocation_year', ''),
                    previous_allocation_amount=Decimal(str(application_data.get('previous_allocation_amount', '0'))),
                    status='submitted'
                )
                
                return JsonResponse({
                    'success': True,
                    'message': 'Application created successfully',
                    'application': {
                        'id': application.id,
                        'application_number': application.application_number,
                        'status': application.status
                    }
                })
                
        except Exception as e:
            return JsonResponse({
                'success': False,
                'message': f'Error creating application: {str(e)}'
            })
    
    def get_locations(self, request, data):
        """Get locations for a specific ward"""
        ward_id = data.get('ward_id')
        if not ward_id:
            return JsonResponse({'success': False, 'message': 'Ward ID required'})
        
        locations = Location.objects.filter(ward_id=ward_id).order_by('name')
        location_list = [{'id': loc.id, 'name': loc.name} for loc in locations]
        
        return JsonResponse({
            'success': True,
            'locations': location_list
        })
    
    def get_sublocations(self, request, data):
        """Get sublocations for a specific location"""
        location_id = data.get('location_id')
        if not location_id:
            return JsonResponse({'success': False, 'message': 'Location ID required'})
        
        sublocations = SubLocation.objects.filter(location_id=location_id).order_by('name')
        sublocation_list = [{'id': sub.id, 'name': sub.name} for sub in sublocations]
        
        return JsonResponse({
            'success': True,
            'sublocations': sublocation_list
        })
    
    def get_villages(self, request, data):
        """Get villages for a specific sublocation"""
        sublocation_id = data.get('sublocation_id')
        if not sublocation_id:
            return JsonResponse({'success': False, 'message': 'Sublocation ID required'})
        
        villages = Village.objects.filter(sublocation_id=sublocation_id).order_by('name')
        village_list = [{'id': vil.id, 'name': vil.name} for vil in villages]
        
        return JsonResponse({
            'success': True,
            'villages': village_list
        })


#security views for admin and reviewers
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth import update_session_auth_hash
from django.contrib import messages
from django.http import JsonResponse
from django.core.paginator import Paginator
from django.db.models import Q, Count
from django.contrib.auth.forms import PasswordChangeForm
from django.utils import timezone
from datetime import datetime, timedelta
from .models import (
    User, SystemSettings, AuditLog, FAQ, Announcement, 
    Application, Allocation, FiscalYear, BursaryCategory,
    Notification, SMSLog
)
from .forms import (
    AdminProfileForm, SystemSettingsForm, FAQForm, 
    AnnouncementForm, NotificationForm
)

def is_admin_or_staff(user):
    """Check if user is admin or staff"""
    return user.is_authenticated and (user.is_staff or user.user_type in ['admin', 'reviewer', 'finance'])

@login_required
@user_passes_test(is_admin_or_staff)
def admin_profile_settings(request):
    """Admin profile settings view"""
    user = request.user
    
    if request.method == 'POST':
        form = AdminProfileForm(request.POST, instance=user)
        if form.is_valid():
            form.save()
            messages.success(request, 'Profile updated successfully!')
            
            # Log the activity
            AuditLog.objects.create(
                user=request.user,
                action='update',
                table_affected='User',
                record_id=str(user.id),
                description=f'Updated profile information',
                ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1')
            )
            
            return redirect('admin_profile_settings')
    else:
        form = AdminProfileForm(instance=user)
    
    # Get recent activity
    recent_activities = AuditLog.objects.filter(user=user).order_by('-timestamp')[:10]
    
    context = {
        'form': form,
        'user': user,
        'recent_activities': recent_activities,
        'page_title': 'Profile Settings',
    }
    return render(request, 'admin/profile_settings.html', context)

@login_required
@user_passes_test(is_admin_or_staff)
def admin_help_support(request):
    """Admin help and support view"""
    # Get all FAQs
    faqs = FAQ.objects.filter(is_active=True).order_by('category', 'order')
    
    # Group FAQs by category
    faq_categories = {}
    for faq in faqs:
        if faq.category not in faq_categories:
            faq_categories[faq.category] = []
        faq_categories[faq.category].append(faq)
    
    # Handle FAQ creation/editing
    if request.method == 'POST':
        if request.user.user_type == 'admin':
            action = request.POST.get('action')
            
            if action == 'add_faq':
                form = FAQForm(request.POST)
                if form.is_valid():
                    form.save()
                    messages.success(request, 'FAQ added successfully!')
                    
                    # Log the activity
                    AuditLog.objects.create(
                        user=request.user,
                        action='create',
                        table_affected='FAQ',
                        description=f'Added new FAQ: {form.cleaned_data["question"][:50]}...',
                        ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1')
                    )
                    
                    return redirect('admin_help_support')
            
            elif action == 'edit_faq':
                faq_id = request.POST.get('faq_id')
                faq = get_object_or_404(FAQ, id=faq_id)
                form = FAQForm(request.POST, instance=faq)
                if form.is_valid():
                    form.save()
                    messages.success(request, 'FAQ updated successfully!')
                    return redirect('admin_help_support')
    
    # Forms for adding/editing FAQs
    faq_form = FAQForm() if request.user.user_type == 'admin' else None
    
    context = {
        'faq_categories': faq_categories,
        'faq_form': faq_form,
        'can_edit': request.user.user_type == 'admin',
        'page_title': 'Help & Support',
    }
    return render(request, 'admin/help_support.html', context)

@login_required
@user_passes_test(is_admin_or_staff)
def admin_preferences(request):
    """Admin preference settings view"""
    # Get all system settings
    settings = SystemSettings.objects.filter(is_active=True).order_by('setting_name')
    
    if request.method == 'POST':
        if request.user.user_type == 'admin':
            setting_name = request.POST.get('setting_name')
            setting_value = request.POST.get('setting_value')
            setting_description = request.POST.get('setting_description', '')
            
            # Update or create setting
            setting, created = SystemSettings.objects.get_or_create(
                setting_name=setting_name,
                defaults={
                    'setting_value': setting_value,
                    'description': setting_description,
                    'updated_by': request.user
                }
            )
            
            if not created:
                setting.setting_value = setting_value
                setting.description = setting_description
                setting.updated_by = request.user
                setting.save()
            
            action = 'created' if created else 'updated'
            messages.success(request, f'Setting {action} successfully!')
            
            # Log the activity
            AuditLog.objects.create(
                user=request.user,
                action='create' if created else 'update',
                table_affected='SystemSettings',
                record_id=str(setting.id),
                description=f'{"Created" if created else "Updated"} system setting: {setting_name}',
                ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1')
            )
            
            return redirect('admin_preferences')
    
    context = {
        'settings': settings,
        'can_edit': request.user.user_type == 'admin',
        'page_title': 'Preferences',
    }
    return render(request, 'admin/preferences.html', context)

@login_required
@user_passes_test(is_admin_or_staff)
def admin_communication(request):
    """Admin communication view"""
    # Get recent notifications and SMS logs
    notifications = Notification.objects.all().order_by('-created_at')[:50]
    sms_logs = SMSLog.objects.all().order_by('-sent_at')[:50]
    announcements = Announcement.objects.all().order_by('-published_date')[:20]
    
    # Pagination
    notification_paginator = Paginator(notifications, 20)
    sms_paginator = Paginator(sms_logs, 20)
    announcement_paginator = Paginator(announcements, 10)
    
    notification_page = request.GET.get('notification_page', 1)
    sms_page = request.GET.get('sms_page', 1)
    announcement_page = request.GET.get('announcement_page', 1)
    
    notifications_paginated = notification_paginator.get_page(notification_page)
    sms_logs_paginated = sms_paginator.get_page(sms_page)
    announcements_paginated = announcement_paginator.get_page(announcement_page)
    
    # Handle form submissions
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'send_notification':
            form = NotificationForm(request.POST)
            if form.is_valid():
                notification = form.save()
                messages.success(request, 'Notification sent successfully!')
                
                # Log the activity
                AuditLog.objects.create(
                    user=request.user,
                    action='create',
                    table_affected='Notification',
                    record_id=str(notification.id),
                    description=f'Sent notification: {notification.title}',
                    ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1')
                )
                
                return redirect('admin_communication')
        
        elif action == 'add_announcement':
            form = AnnouncementForm(request.POST)
            if form.is_valid():
                announcement = form.save(commit=False)
                announcement.created_by = request.user
                announcement.save()
                messages.success(request, 'Announcement created successfully!')
                
                # Log the activity
                AuditLog.objects.create(
                    user=request.user,
                    action='create',
                    table_affected='Announcement',
                    record_id=str(announcement.id),
                    description=f'Created announcement: {announcement.title}',
                    ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1')
                )
                
                return redirect('admin_communication')
    
    # Forms
    notification_form = NotificationForm()
    announcement_form = AnnouncementForm()
    
    # Communication statistics
    stats = {
        'total_notifications': Notification.objects.count(),
        'unread_notifications': Notification.objects.filter(is_read=False).count(),
        'total_sms': SMSLog.objects.count(),
        'pending_sms': SMSLog.objects.filter(status='pending').count(),
        'active_announcements': Announcement.objects.filter(
            is_active=True,
            expiry_date__gt=timezone.now()
        ).count(),
    }
    
    context = {
        'notifications': notifications_paginated,
        'sms_logs': sms_logs_paginated,
        'announcements': announcements_paginated,
        'notification_form': notification_form,
        'announcement_form': announcement_form,
        'stats': stats,
        'page_title': 'Communication',
    }
    return render(request, 'admin/communication.html', context)

@login_required
@user_passes_test(is_admin_or_staff)
def admin_security_audit(request):
    """Admin security and audit view"""
    # Get audit logs with filtering
    audit_logs = AuditLog.objects.all().order_by('-timestamp')
    
    # Apply filters
    action_filter = request.GET.get('action')
    user_filter = request.GET.get('user')
    date_from = request.GET.get('date_from')
    date_to = request.GET.get('date_to')
    
    if action_filter:
        audit_logs = audit_logs.filter(action=action_filter)
    
    if user_filter:
        audit_logs = audit_logs.filter(user__username__icontains=user_filter)
    
    if date_from:
        try:
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d').date()
            audit_logs = audit_logs.filter(timestamp__date__gte=date_from_obj)
        except ValueError:
            pass
    
    if date_to:
        try:
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d').date()
            audit_logs = audit_logs.filter(timestamp__date__lte=date_to_obj)
        except ValueError:
            pass
    
    # Pagination
    paginator = Paginator(audit_logs, 25)
    page_number = request.GET.get('page')
    audit_logs_paginated = paginator.get_page(page_number)
    
    # Security statistics
    today = timezone.now().date()
    last_7_days = today - timedelta(days=7)
    last_30_days = today - timedelta(days=30)
    
    security_stats = {
        'total_logins_today': AuditLog.objects.filter(
            action='login',
            timestamp__date=today
        ).count(),
        'total_logins_7_days': AuditLog.objects.filter(
            action='login',
            timestamp__date__gte=last_7_days
        ).count(),
        'total_logins_30_days': AuditLog.objects.filter(
            action='login',
            timestamp__date__gte=last_30_days
        ).count(),
        'failed_login_attempts': AuditLog.objects.filter(
            description__icontains='failed login',
            timestamp__date__gte=last_7_days
        ).count(),
        'total_users': User.objects.count(),
        'active_sessions': User.objects.filter(last_login__date=today).count(),
    }
    
    # Get unique actions and users for filter dropdowns
    unique_actions = AuditLog.objects.values_list('action', flat=True).distinct()
    unique_users = User.objects.filter(audit_logs__isnull=False).distinct()
    
    # Handle password change
    password_form = None
    if request.method == 'POST' and 'change_password' in request.POST:
        password_form = PasswordChangeForm(request.user, request.POST)
        if password_form.is_valid():
            user = password_form.save()
            update_session_auth_hash(request, user)
            messages.success(request, 'Password changed successfully!')
            
            # Log password change
            AuditLog.objects.create(
                user=request.user,
                action='update',
                table_affected='User',
                record_id=str(user.id),
                description='Changed password',
                ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1')
            )
            
            return redirect('admin_security_audit')
    else:
        password_form = PasswordChangeForm(request.user)
    
    context = {
        'audit_logs': audit_logs_paginated,
        'security_stats': security_stats,
        'unique_actions': unique_actions,
        'unique_users': unique_users,
        'password_form': password_form,
        'filters': {
            'action': action_filter,
            'user': user_filter,
            'date_from': date_from,
            'date_to': date_to,
        },
        'page_title': 'Security & Audit',
    }
    return render(request, 'admin/security_audit.html', context)

# AJAX views for dynamic content
@login_required
@user_passes_test(is_admin_or_staff)
def get_audit_log_details(request, log_id):
    """Get detailed information about an audit log entry"""
    log_entry = get_object_or_404(AuditLog, id=log_id)
    
    data = {
        'id': log_entry.id,
        'user': str(log_entry.user) if log_entry.user else 'System',
        'action': log_entry.get_action_display(),
        'table_affected': log_entry.table_affected,
        'record_id': log_entry.record_id,
        'description': log_entry.description,
        'ip_address': log_entry.ip_address,
        'timestamp': log_entry.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
    }
    
    return JsonResponse(data)

@login_required
@user_passes_test(is_admin_or_staff)
def toggle_faq_status(request, faq_id):
    """Toggle FAQ active status"""
    if request.user.user_type != 'admin':
        return JsonResponse({'success': False, 'error': 'Permission denied'})
    
    faq = get_object_or_404(FAQ, id=faq_id)
    faq.is_active = not faq.is_active
    faq.save()
    
    # Log the activity
    AuditLog.objects.create(
        user=request.user,
        action='update',
        table_affected='FAQ',
        record_id=str(faq.id),
        description=f'{"Activated" if faq.is_active else "Deactivated"} FAQ: {faq.question[:50]}...',
        ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1')
    )
    
    return JsonResponse({
        'success': True,
        'is_active': faq.is_active,
        'status_text': 'Active' if faq.is_active else 'Inactive'
    })

@login_required
@user_passes_test(is_admin_or_staff)
def toggle_announcement_status(request, announcement_id):
    """Toggle announcement active status"""
    if request.user.user_type != 'admin':
        return JsonResponse({'success': False, 'error': 'Permission denied'})
    
    announcement = get_object_or_404(Announcement, id=announcement_id)
    announcement.is_active = not announcement.is_active
    announcement.save()
    
    # Log the activity
    AuditLog.objects.create(
        user=request.user,
        action='update',
        table_affected='Announcement',
        record_id=str(announcement.id),
        description=f'{"Activated" if announcement.is_active else "Deactivated"} announcement: {announcement.title}',
        ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1')
    )
    
    return JsonResponse({
        'success': True,
        'is_active': announcement.is_active,
        'status_text': 'Active' if announcement.is_active else 'Inactive'
    })

@login_required
@user_passes_test(is_admin_or_staff)
def delete_system_setting(request, setting_id):
    """Delete a system setting"""
    if request.user.user_type != 'admin':
        return JsonResponse({'success': False, 'error': 'Permission denied'})
    
    setting = get_object_or_404(SystemSettings, id=setting_id)
    setting_name = setting.setting_name
    setting.delete()
    
    # Log the activity
    AuditLog.objects.create(
        user=request.user,
        action='delete',
        table_affected='SystemSettings',
        record_id=str(setting_id),
        description=f'Deleted system setting: {setting_name}',
        ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1')
    )
    
    return JsonResponse({'success': True})