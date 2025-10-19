from django.core.management.base import BaseCommand
from django.contrib.auth.hashers import make_password
from django.utils import timezone
from decimal import Decimal
import random
from datetime import datetime, date, timedelta
from django.db import transaction

from kiharu_system.models import (
    User, Ward, Location, SubLocation, Village, Institution, 
    FiscalYear, BursaryCategory, Applicant, Guardian, 
    SiblingInformation, Application, Document, Review, 
    Allocation, Notification, SMSLog, AuditLog, SystemSettings,
    FAQ, Announcement
)


class Command(BaseCommand):
    help = 'Seed the database with sample data for Kiharu Constituency, Murang\'a County'

    def add_arguments(self, parser):
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Clear existing data before seeding',
        )

    def handle(self, *args, **options):
        if options['clear']:
            self.stdout.write('Clearing existing data...')
            self.clear_data()

        self.stdout.write('Starting data seeding...')
        
        with transaction.atomic():
            self.create_users()
            self.create_geographic_data()
            self.create_institutions()
            self.create_fiscal_years_and_categories()
            self.create_applicants_and_guardians()
            self.create_applications()
            self.create_reviews_and_allocations()
            self.create_system_data()
            
        self.stdout.write(
            self.style.SUCCESS('Successfully seeded the database!')
        )

    def clear_data(self):
        """Clear all existing data"""
        models_to_clear = [
            Announcement, FAQ, SystemSettings, AuditLog, SMSLog,
            Notification, Allocation, Review, Document, Application,
            SiblingInformation, Guardian, Applicant, BursaryCategory,
            FiscalYear, Institution, Village, SubLocation, Location,
            Ward, User
        ]
        
        for model in models_to_clear:
            model.objects.all().delete()

    def create_users(self):
        """Create system users"""
        self.stdout.write('Creating users...')
        
        # Create superuser
        if not User.objects.filter(username='admin').exists():
            User.objects.create_user(
                username='admin',
                email='admin@kiharu.go.ke',
                password='admin123',
                first_name='System',
                last_name='Administrator',
                user_type='admin',
                is_staff=True,
                is_superuser=True
            )

        # Create staff users(G!&HxdU8DAHm)
        staff_users = [
            {
                'username': 'mwangi.reviewer',
                'email': 'mwangi@kiharu.go.ke',
                'first_name': 'John',
                'last_name': 'Mwangi',
                'user_type': 'reviewer',
                'id_number': '12345678'
            },
            {
                'username': 'wanjiku.finance',
                'email': 'wanjiku@kiharu.go.ke',
                'first_name': 'Mary',
                'last_name': 'Wanjiku',
                'user_type': 'finance',
                'id_number': '87654321'
            },
            {
                'username': 'kamau.reviewer',
                'email': 'kamau@kiharu.go.ke',
                'first_name': 'Peter',
                'last_name': 'Kamau',
                'user_type': 'reviewer',
                'id_number': '11223344'
            }
        ]

        for user_data in staff_users:
            if not User.objects.filter(username=user_data['username']).exists():
                User.objects.create_user(
                    username=user_data['username'],
                    email=user_data['email'],
                    password='password123',
                    first_name=user_data['first_name'],
                    last_name=user_data['last_name'],
                    user_type=user_data['user_type'],
                    id_number=user_data['id_number'],
                    phone_number=f'+254{random.randint(700000000, 799999999)}',
                    is_staff=True
                )

    def create_geographic_data(self):
        """Create geographic data for Kiharu Constituency"""
        self.stdout.write('Creating geographic data...')
        
        # Kiharu Constituency Wards
        wards_data = [
            {
                'name': 'Gaichanjiru',
                'description': 'Agricultural ward with tea and coffee farming'
            },
            {
                'name': 'Mbiri',
                'description': 'Mixed farming area with good road connectivity'
            },
            {
                'name': 'Township',
                'description': 'Urban center of Kiharu with commercial activities'
            },
            {
                'name': 'Mugoiri',
                'description': 'Rural ward with subsistence farming'
            },
            {
                'name': 'Wangu',
                'description': 'Predominantly agricultural with small-scale farming'
            }
        ]

        wards = {}
        for ward_data in wards_data:
            ward, created = Ward.objects.get_or_create(
                name=ward_data['name'],
                defaults={'description': ward_data['description']}
            )
            wards[ward_data['name']] = ward

        # Locations within wards
        locations_data = {
            'Gaichanjiru': ['Gaichanjiru', 'Kigwandi', 'Mukuruweini'],
            'Mbiri': ['Mbiri', 'Karega', 'Gitare'],
            'Township': ['Township', 'Kenol', 'Kiria-ini'],
            'Mugoiri': ['Mugoiri', 'Kagongo', 'Kiruri'],
            'Wangu': ['Wangu', 'Mahiga', 'Kirimukuyu']
        }

        locations = {}
        for ward_name, location_names in locations_data.items():
            ward = wards[ward_name]
            for location_name in location_names:
                location, created = Location.objects.get_or_create(
                    name=location_name,
                    ward=ward
                )
                locations[f"{ward_name}_{location_name}"] = location

        # Sub-locations
        sublocations_data = {
            'Gaichanjiru_Gaichanjiru': ['Gaichanjiru Central', 'Kamunyaka'],
            'Gaichanjiru_Kigwandi': ['Kigwandi', 'Kamacharia'],
            'Gaichanjiru_Mukuruweini': ['Mukuruweini East', 'Mukuruweini West'],
            'Mbiri_Mbiri': ['Mbiri Central', 'Kiria'],
            'Mbiri_Karega': ['Karega A', 'Karega B'],
            'Mbiri_Gitare': ['Gitare East', 'Gitare West'],
            'Township_Township': ['Township Central', 'Makongeni'],
            'Township_Kenol': ['Kenol Town', 'Kenol Market'],
            'Township_Kiria-ini': ['Kiria-ini North', 'Kiria-ini South'],
            'Mugoiri_Mugoiri': ['Mugoiri Central', 'Kanyoni'],
            'Mugoiri_Kagongo': ['Kagongo A', 'Kagongo B'],
            'Mugoiri_Kiruri': ['Kiruri East', 'Kiruri West'],
            'Wangu_Wangu': ['Wangu Central', 'Kiriaini'],
            'Wangu_Mahiga': ['Mahiga East', 'Mahiga West'],
            'Wangu_Kirimukuyu': ['Kirimukuyu A', 'Kirimukuyu B'],
        }


        sublocations = {}
        for location_key, sublocation_names in sublocations_data.items():
            if location_key in locations:
                location = locations[location_key]
                for sublocation_name in sublocation_names:
                    sublocation, created = SubLocation.objects.get_or_create(
                        name=sublocation_name,
                        location=location
                    )
                    sublocations[f"{location_key}_{sublocation_name}"] = sublocation

        # Villages
        village_names = [
            'Kiamuriuki', 'Kambaa', 'Githiga', 'Gituamba', 'Karatu',
            'Kiamwangi', 'Kihingo', 'Kiriaini', 'Mukuyu', 'Ndururuno',
            'Nginda', 'Ruguru', 'Thika', 'Wamumu', 'Gatanga'
        ]

        for sublocation_key, sublocation in sublocations.items():
            # Create 2-3 villages per sublocation
            selected_villages = random.sample(village_names, random.randint(2, 3))
            for village_name in selected_villages:
                Village.objects.get_or_create(
                    name=village_name,
                    sublocation=sublocation
                )

        self.stdout.write(f'Created {Ward.objects.count()} wards, {Location.objects.count()} locations')

    def create_institutions(self):
        """Create educational institutions"""
        self.stdout.write('Creating institutions...')
        
        institutions_data = [
            # High Schools
            {
                'name': 'Kiharu Girls High School',
                'institution_type': 'highschool',
                'county': 'Murang\'a',
                'postal_address': 'P.O. Box 123 Kiharu',
                'phone_number': '+254711234567'
            },
            {
                'name': 'Mugoiri Boys Secondary School',
                'institution_type': 'highschool',
                'county': 'Murang\'a',
                'postal_address': 'P.O. Box 456 Mugoiri',
                'phone_number': '+254722345678'
            },
            {
                'name': 'Township Mixed Secondary School',
                'institution_type': 'highschool',
                'county': 'Murang\'a',
                'postal_address': 'P.O. Box 789 Township',
                'phone_number': '+254733456789'
            },
            {
                'name': 'Mbiri Secondary School',
                'institution_type': 'highschool',
                'county': 'Murang\'a',
                'postal_address': 'P.O. Box 321 Mbiri',
                'phone_number': '+254744567890'
            },
            # Universities
            {
                'name': 'University of Nairobi',
                'institution_type': 'university',
                'county': 'Nairobi',
                'postal_address': 'P.O. Box 30197 Nairobi',
                'phone_number': '+254204491000'
            },
            {
                'name': 'Kenyatta University',
                'institution_type': 'university',
                'county': 'Kiambu',
                'postal_address': 'P.O. Box 43844 Nairobi',
                'phone_number': '+254208710901'
            },
            {
                'name': 'Murang\'a University of Technology',
                'institution_type': 'university',
                'county': 'Murang\'a',
                'postal_address': 'P.O. Box 75 Murang\'a',
                'phone_number': '+254060230208'
            },
            # Colleges
            {
                'name': 'Murang\'a Teachers College',
                'institution_type': 'college',
                'county': 'Murang\'a',
                'postal_address': 'P.O. Box 14 Murang\'a',
                'phone_number': '+254060212345'
            },
            {
                'name': 'Kenya Medical Training College - Murang\'a',
                'institution_type': 'college',
                'county': 'Murang\'a',
                'postal_address': 'P.O. Box 567 Murang\'a',
                'phone_number': '+254060234567'
            },
            # Special Schools
            {
                'name': 'Kiharu Special School',
                'institution_type': 'special_school',
                'county': 'Murang\'a',
                'postal_address': 'P.O. Box 890 Kiharu',
                'phone_number': '+254755123456'
            }
        ]

        for institution_data in institutions_data:
            Institution.objects.get_or_create(
                name=institution_data['name'],
                defaults=institution_data
            )

        self.stdout.write(f'Created {Institution.objects.count()} institutions')

    def create_fiscal_years_and_categories(self):
        """Create fiscal years and bursary categories"""
        self.stdout.write('Creating fiscal years and categories...')
        
        # Create fiscal years
        fiscal_years_data = [
            {
                'name': '2023-2024',
                'start_date': date(2023, 7, 1),
                'end_date': date(2024, 6, 30),
                'total_allocation': Decimal('50000000.00'),
                'is_active': False
            },
            {
                'name': '2024-2025',
                'start_date': date(2024, 7, 1),
                'end_date': date(2025, 6, 30),
                'total_allocation': Decimal('75000000.00'),
                'is_active': True
            }
        ]

        fiscal_years = {}
        for fy_data in fiscal_years_data:
            fy, created = FiscalYear.objects.get_or_create(
                name=fy_data['name'],
                defaults=fy_data
            )
            fiscal_years[fy_data['name']] = fy

        # Create bursary categories
        categories_data = [
            {
                'name': 'High School Bursary',
                'category_type': 'highschool',
                'allocation_amount': Decimal('20000000.00'),
                'max_amount_per_applicant': Decimal('30000.00')
            },
            {
                'name': 'University Bursary',
                'category_type': 'university',
                'allocation_amount': Decimal('35000000.00'),
                'max_amount_per_applicant': Decimal('80000.00')
            },
            {
                'name': 'College Bursary',
                'category_type': 'college',
                'allocation_amount': Decimal('15000000.00'),
                'max_amount_per_applicant': Decimal('50000.00')
            },
            {
                'name': 'Special Needs Education',
                'category_type': 'special_school',
                'allocation_amount': Decimal('5000000.00'),
                'max_amount_per_applicant': Decimal('60000.00')
            }
        ]

        for fy_name, fy in fiscal_years.items():
            for cat_data in categories_data:
                BursaryCategory.objects.get_or_create(
                    name=cat_data['name'],
                    category_type=cat_data['category_type'],
                    fiscal_year=fy,
                    defaults={
                        'allocation_amount': cat_data['allocation_amount'],
                        'max_amount_per_applicant': cat_data['max_amount_per_applicant']
                    }
                )

        self.stdout.write(f'Created {FiscalYear.objects.count()} fiscal years, {BursaryCategory.objects.count()} categories')

    def create_applicants_and_guardians(self):
        """Create applicant users and their profiles"""
        self.stdout.write('Creating applicants...')
        
        # Kenyan names
        male_first_names = ['John', 'Peter', 'David', 'James', 'Samuel', 'Joseph', 'Michael', 'Daniel', 'Paul', 'Francis']
        female_first_names = ['Mary', 'Jane', 'Grace', 'Joyce', 'Ann', 'Catherine', 'Margaret', 'Elizabeth', 'Lucy', 'Sarah']
        kikuyu_surnames = ['Mwangi', 'Kamau', 'Wanjiku', 'Njeri', 'Gitau', 'Muchiri', 'Karanja', 'Maina', 'Waithaka', 'Ngugi']
        
        wards = list(Ward.objects.all())
        locations = list(Location.objects.all())
        sublocations = list(SubLocation.objects.all())
        villages = list(Village.objects.all())

        # Create 50 applicant users
        for i in range(50):
            # Generate user data
            is_male = random.choice([True, False])
            first_name = random.choice(male_first_names if is_male else female_first_names)
            last_name = random.choice(kikuyu_surnames)
            username = f"{first_name.lower()}.{last_name.lower()}{i}"
            
            # Create user
            user = User.objects.create_user(
                username=username,
                email=f"{username}@gmail.com",
                password='password123',
                first_name=first_name,
                last_name=last_name,
                user_type='applicant',
                id_number=f"{random.randint(20000000, 39999999)}",
                phone_number=f"+254{random.randint(700000000, 799999999)}"
            )

            # Create applicant profile
            birth_year = random.randint(1990, 2006)
            birth_month = random.randint(1, 12)
            birth_day = random.randint(1, 28)
            
            ward = random.choice(wards)
            location = random.choice([loc for loc in locations if loc.ward == ward])
            sublocation = random.choice([sub for sub in sublocations if sub.location == location])
            village = random.choice([vil for vil in villages if vil.sublocation == sublocation])

            applicant = Applicant.objects.create(
                user=user,
                gender='M' if is_male else 'F',
                date_of_birth=date(birth_year, birth_month, birth_day),
                id_number=user.id_number,
                ward=ward,
                location=location,
                sublocation=sublocation,
                village=village,
                physical_address=f"{village.name} Village, {sublocation.name}",
                postal_address=f"P.O. Box {random.randint(1, 999)} {location.name}",
                special_needs=random.choice([True, False]) if random.random() < 0.1 else False,
                special_needs_description="Visual impairment" if random.random() < 0.5 else "Physical disability"
            )

            # Create guardians
            relationships = ['father', 'mother', 'guardian']
            for j, relationship in enumerate(relationships[:random.randint(1, 2)]):
                guardian_gender = 'M' if relationship == 'father' else 'F'
                guardian_first = random.choice(male_first_names if guardian_gender == 'M' else female_first_names)
                
                Guardian.objects.create(
                    applicant=applicant,
                    name=f"{guardian_first} {last_name}",
                    relationship=relationship,
                    phone_number=f"+254{random.randint(700000000, 799999999)}",
                    email=f"{guardian_first.lower()}.{last_name.lower()}@gmail.com" if random.random() < 0.3 else "",
                    occupation=random.choice(['Farmer', 'Teacher', 'Small Business', 'Casual Laborer', 'Civil Servant']),
                    monthly_income=Decimal(random.randint(5000, 50000)),
                    id_number=f"{random.randint(15000000, 35000000)}"
                )

            # Create siblings (sometimes)
            if random.random() < 0.7:  # 70% chance of having siblings
                num_siblings = random.randint(1, 4)
                for k in range(num_siblings):
                    sibling_gender = random.choice([True, False])
                    sibling_first = random.choice(male_first_names if sibling_gender else female_first_names)
                    
                    SiblingInformation.objects.create(
                        applicant=applicant,
                        name=f"{sibling_first} {last_name}",
                        age=random.randint(5, 25),
                        education_level=random.choice(['Primary', 'Secondary', 'College', 'University', 'Not in school']),
                        school_name=random.choice(['Kiharu Primary', 'Mbiri Secondary', 'Local College', ''])
                    )

        self.stdout.write(f'Created {Applicant.objects.count()} applicants with guardians and siblings')

    def create_applications(self):
        """Create bursary applications"""
        self.stdout.write('Creating applications...')
        
        applicants = list(Applicant.objects.all())
        fiscal_year = FiscalYear.objects.get(is_active=True)
        categories = list(BursaryCategory.objects.filter(fiscal_year=fiscal_year))
        institutions = list(Institution.objects.all())
        
        statuses = ['submitted', 'under_review', 'approved', 'rejected', 'disbursed']
        
        for applicant in applicants:
            # Create 1-2 applications per applicant
            num_applications = random.randint(1, 2)
            
            for i in range(num_applications):
                category = random.choice(categories)
                # Match institution type with category
                matching_institutions = [inst for inst in institutions 
                                       if inst.institution_type == category.category_type]
                if not matching_institutions:
                    continue
                    
                institution = random.choice(matching_institutions)
                
                # Generate financial data
                total_fees = Decimal(random.randint(20000, 200000))
                fees_paid = Decimal(random.randint(0, int(total_fees * Decimal('0.3'))))
                fees_balance = total_fees - fees_paid
                amount_requested = min(fees_balance, category.max_amount_per_applicant)

                
                application = Application.objects.create(
                    applicant=applicant,
                    fiscal_year=fiscal_year,
                    bursary_category=category,
                    institution=institution,
                    status=random.choice(statuses),
                    admission_number=f"ADM/{random.randint(1000, 9999)}/2024",
                    year_of_study=random.randint(1, 4),
                    course_name=random.choice(['BSc Computer Science', 'BA Economics', 'Diploma in Teaching', 'Certificate in ICT']) if category.category_type in ['university', 'college'] else None,
                    expected_completion_date=date(2025 + random.randint(0, 3), random.randint(1, 12), random.randint(1, 28)),
                    total_fees_payable=total_fees,
                    fees_paid=fees_paid,
                    fees_balance=fees_balance,
                    amount_requested=amount_requested,
                    other_bursaries=random.choice([True, False]) if random.random() < 0.3 else False,
                    other_bursaries_amount=Decimal(random.randint(5000, 30000)) if random.random() < 0.3 else Decimal('0'),
                    other_bursaries_source="CDF Bursary" if random.random() < 0.3 else "",
                    is_orphan=random.choice([True, False]) if random.random() < 0.2 else False,
                    is_disabled=applicant.special_needs,
                    has_chronic_illness=random.choice([True, False]) if random.random() < 0.1 else False,
                    chronic_illness_description="Diabetes" if random.random() < 0.5 else "Asthma",
                    previous_allocation=random.choice([True, False]) if random.random() < 0.4 else False,
                    previous_allocation_year="2023-2024" if random.random() < 0.4 else "",
                    previous_allocation_amount=Decimal(random.randint(10000, 50000)) if random.random() < 0.4 else Decimal('0')
                )

        self.stdout.write(f'Created {Application.objects.count()} applications')

    def create_reviews_and_allocations(self):
        """Create reviews and allocations for applications"""
        self.stdout.write('Creating reviews and allocations...')
        
        reviewers = list(User.objects.filter(user_type='reviewer'))
        finance_officers = list(User.objects.filter(user_type='finance'))
        applications = list(Application.objects.exclude(status='draft'))
        
        # Create reviews
        for application in applications:
            if application.status in ['under_review', 'approved', 'rejected', 'disbursed']:
                reviewer = random.choice(reviewers)
                
                if application.status == 'approved':
                    recommendation = 'approve'
                    recommended_amount = application.amount_requested * Decimal('0.8')  # 80% of requested
                elif application.status == 'rejected':
                    recommendation = 'reject'
                    recommended_amount = None
                else:
                    recommendation = random.choice(['approve', 'reject', 'more_info'])
                    recommended_amount = application.amount_requested * Decimal(str(random.uniform(0.5, 1.0))) if recommendation == 'approve' else None

                Review.objects.create(
                    application=application,
                    reviewer=reviewer,
                    comments=random.choice([
                        "Application meets all requirements. Recommend approval.",
                        "Genuine case requiring financial assistance.",
                        "Missing some documentation. Request additional information.",
                        "Family income seems sufficient. Recommend rejection.",
                        "Excellent academic performance. Strong recommendation for approval."
                    ]),
                    recommendation=recommendation,
                    recommended_amount=recommended_amount,
                    review_date=timezone.now() - timedelta(days=random.randint(1, 30))
                )

        # Create allocations for approved applications
        approved_applications = Application.objects.filter(status__in=['approved', 'disbursed'])
        for application in approved_applications:
            review = application.reviews.first()
            amount_allocated = review.recommended_amount if review and review.recommended_amount else application.amount_requested * Decimal('0.7')
            
            allocation = Allocation.objects.create(
                application=application,
                amount_allocated=amount_allocated,
                allocation_date=date.today() - timedelta(days=random.randint(1, 60)),
                approved_by=random.choice(reviewers),
                cheque_number=f"CHQ/{random.randint(100000, 999999)}",
                is_disbursed=application.status == 'disbursed',
                disbursement_date=date.today() - timedelta(days=random.randint(1, 30)) if application.status == 'disbursed' else None,
                disbursed_by=random.choice(finance_officers) if application.status == 'disbursed' else None,
                remarks="Funds disbursed as per approval" if application.status == 'disbursed' else "Approved for disbursement"
            )

        self.stdout.write(f'Created {Review.objects.count()} reviews and {Allocation.objects.count()} allocations')

    def create_system_data(self):
        """Create system settings, FAQs, and announcements"""
        self.stdout.write('Creating system data...')
        
        admin_user = User.objects.filter(is_superuser=True).first()
        
        # System settings
        settings_data = [
            {
                'setting_name': 'APPLICATION_DEADLINE',
                'setting_value': '2024-12-31',
                'description': 'Last date for submitting applications'
            },
            {
                'setting_name': 'MINIMUM_AMOUNT',
                'setting_value': '5000',
                'description': 'Minimum bursary amount that can be allocated'
            },
            {
                'setting_name': 'SMS_ENABLED',
                'setting_value': 'true',
                'description': 'Enable SMS notifications'
            },
            {
                'setting_name': 'EMAIL_ENABLED',
                'setting_value': 'true',
                'description': 'Enable email notifications'
            }
        ]

        for setting_data in settings_data:
            SystemSettings.objects.get_or_create(
                setting_name=setting_data['setting_name'],
                defaults={
                    'setting_value': setting_data['setting_value'],
                    'description': setting_data['description'],
                    'updated_by': admin_user
                }
            )

        # FAQs
        faqs_data = [
            {
                'question': 'Who is eligible to apply for the Kiharu Constituency bursary?',
                'answer': 'Students from Kiharu Constituency who are in financial need and enrolled in recognized educational institutions.',
                'category': 'Eligibility',
                'order': 1
            },
            {
                'question': 'What documents do I need to submit with my application?',
                'answer': 'You need ID card, admission letter, fee structure, fee statement, and parent/guardian ID.',
                'category': 'Documentation',
                'order': 2
            },
            {
                'question': 'When is the application deadline?',
                'answer': 'Applications are accepted throughout the year, but priority is given to early submissions.',
                'category': 'Timeline',
                'order': 3
            },
            {
                'question': 'How will I know the status of my application?',
                'answer': 'You will receive SMS and email notifications about your application status.',
                'category': 'Communication',
                'order': 4
            }
        ]

        for faq_data in faqs_data:
            FAQ.objects.get_or_create(
                question=faq_data['question'],
                defaults=faq_data
            )

        # Announcements
        announcements_data = [
            {
                'title': 'Bursary Applications Now Open for 2024-2025',
                'content': 'The Kiharu Constituency Bursary Fund is now accepting applications for the 2024-2025 academic year. Eligible students are encouraged to apply early.',
                'published_date': timezone.now() - timedelta(days=30),
                'expiry_date': timezone.now() + timedelta(days=60),
                'created_by': admin_user
            },
            {
                'title': 'Required Documents Update',
                'content': 'Please ensure all required documents are submitted in PDF format. Incomplete applications will be returned.',
                'published_date': timezone.now() - timedelta(days=15),
                'expiry_date': timezone.now() + timedelta(days=45),
                'created_by': admin_user
            }
        ]

        for announcement_data in announcements_data:
            Announcement.objects.get_or_create(
                title=announcement_data['title'],
                defaults=announcement_data
            )

        # Create some notifications for applicants
        applicant_users = list(User.objects.filter(user_type='applicant'))
        applications = list(Application.objects.all())
        
        notification_templates = [
            {
                'notification_type': 'application_status',
                'title': 'Application Status Update',
                'message': 'Your bursary application has been reviewed and approved.'
            },
            {
                'notification_type': 'document_request',
                'title': 'Additional Documents Required',
                'message': 'Please submit your fee statement to complete your application.'
            },
            {
                'notification_type': 'allocation',
                'title': 'Bursary Allocated',
                'message': 'Congratulations! Your bursary has been allocated. Check your application for details.'
            },
            {
                'notification_type': 'disbursement',
                'title': 'Funds Disbursed',
                'message': 'Your bursary funds have been disbursed to your institution.'
            }
        ]

        for i, user in enumerate(random.sample(applicant_users, min(20, len(applicant_users)))):
            template = random.choice(notification_templates)
            user_applications = [app for app in applications if app.applicant.user == user]
            related_app = random.choice(user_applications) if user_applications else None
            
            Notification.objects.create(
                user=user,
                notification_type=template['notification_type'],
                title=template['title'],
                message=template['message'],
                related_application=related_app,
                is_read=random.choice([True, False]),
                created_at=timezone.now() - timedelta(days=random.randint(1, 30))
            )

        # Create some SMS logs
        for i in range(30):
            user = random.choice(applicant_users)
            user_applications = [app for app in applications if app.applicant.user == user]
            related_app = random.choice(user_applications) if user_applications else None
            
            SMSLog.objects.create(
                recipient=user,
                phone_number=user.phone_number,
                message=random.choice([
                    f"Dear {user.first_name}, your bursary application has been received and is under review.",
                    f"Hello {user.first_name}, your bursary application has been approved. Congratulations!",
                    f"Dear {user.first_name}, please submit additional documents for your bursary application.",
                    f"Hi {user.first_name}, your bursary funds have been disbursed to your school."
                ]),
                related_application=related_app,
                status=random.choice(['sent', 'delivered', 'failed']),
                sent_at=timezone.now() - timedelta(days=random.randint(1, 60)),
                delivery_status=random.choice(['delivered', 'failed', 'pending'])
            )

        # Create audit logs
        all_users = list(User.objects.all())
        actions = ['create', 'update', 'view', 'approve', 'reject', 'login']
        tables = ['Application', 'Applicant', 'User', 'Allocation', 'Review']
        
        for i in range(100):
            user = random.choice(all_users)
            action = random.choice(actions)
            table = random.choice(tables)
            
            AuditLog.objects.create(
                user=user,
                action=action,
                table_affected=table,
                record_id=str(random.randint(1, 100)),
                description=f"User {user.username} performed {action} on {table}",
                ip_address=f"192.168.1.{random.randint(1, 254)}",
                timestamp=timezone.now() - timedelta(days=random.randint(1, 90))
            )

        self.stdout.write(f'Created system data: {SystemSettings.objects.count()} settings, '
                         f'{FAQ.objects.count()} FAQs, {Announcement.objects.count()} announcements, '
                         f'{Notification.objects.count()} notifications, {SMSLog.objects.count()} SMS logs, '
                         f'{AuditLog.objects.count()} audit logs')

    def get_random_kenyan_phone(self):
        """Generate a random Kenyan phone number"""
        return f"+254{random.randint(700000000, 799999999)}"

    def get_random_id_number(self):
        """Generate a random Kenyan ID number"""
        return f"{random.randint(20000000, 39999999)}"