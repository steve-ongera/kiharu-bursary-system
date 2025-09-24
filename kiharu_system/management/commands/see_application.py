import random
import datetime
from django.core.management.base import BaseCommand
from django.utils import timezone
from kiharu_system.models import Applicant, Application, FiscalYear, BursaryCategory, Institution


class Command(BaseCommand):
    help = "Create applications for applicants who don't have any in the current fiscal year."

    def handle(self, *args, **kwargs):
        fiscal_year = FiscalYear.objects.filter(is_active=True).first()
        if not fiscal_year:
            self.stdout.write(self.style.ERROR("❌ No active Fiscal Year found. Please activate one."))
            return

        categories = {c.category_type: c for c in BursaryCategory.objects.filter(fiscal_year=fiscal_year)}
        if not categories:
            self.stdout.write(self.style.ERROR("❌ No Bursary Categories found for the active fiscal year."))
            return

        applicants = Applicant.objects.all()
        created_count = 0

        for applicant in applicants:
            # Skip if applicant already has application in this fiscal year
            if Application.objects.filter(applicant=applicant, fiscal_year=fiscal_year).exists():
                continue

            institution = Institution.objects.order_by("?").first()
            if not institution:
                continue

            category = categories.get(institution.institution_type)
            if not category:
                continue

            # Financials
            total_fees = random.randint(20000, 80000)
            fees_paid = random.randint(5000, int(total_fees * 0.7))
            balance = total_fees - fees_paid
            max_request = min(balance, int(category.max_amount_per_applicant))
            amount_requested = random.randint(5000, max_request) if max_request > 5000 else max_request

            # Random academic info
            admission_number = f"ADM-{random.randint(1000,9999)}"
            year_of_study = random.randint(1, 4)
            course_name = "Bachelor of Arts" if institution.institution_type in ["college", "university"] else None
            expected_completion_date = fiscal_year.end_date + datetime.timedelta(days=random.randint(30, 365))

            # Random submission date between fiscal year range
            start_date = fiscal_year.start_date
            end_date = fiscal_year.end_date
            random_date = start_date + datetime.timedelta(
                days=random.randint(0, (end_date - start_date).days)
            )
            random_datetime = datetime.datetime.combine(random_date, datetime.time.min, tzinfo=datetime.timezone.utc)

            # Create application
            app = Application.objects.create(
                applicant=applicant,
                fiscal_year=fiscal_year,
                bursary_category=category,
                institution=institution,
                status="submitted",
                admission_number=admission_number,
                year_of_study=year_of_study,
                course_name=course_name,
                expected_completion_date=expected_completion_date,
                total_fees_payable=total_fees,
                fees_paid=fees_paid,
                fees_balance=balance,
                amount_requested=amount_requested,
                other_bursaries=random.choice([True, False]),
                other_bursaries_amount=0,
                other_bursaries_source=None,
                is_orphan=random.choice([True, False]),
                is_disabled=random.choice([True, False]),
                has_chronic_illness=random.choice([True, False]),
                date_submitted=random_datetime,
            )

            created_count += 1
            self.stdout.write(self.style.SUCCESS(f"✅ Created application {app.application_number} for {applicant}"))

        self.stdout.write(self.style.SUCCESS(f"🎉 Done! Created {created_count} applications for fiscal year {fiscal_year.name}"))
