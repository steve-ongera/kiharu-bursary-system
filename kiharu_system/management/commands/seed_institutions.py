from django.core.management.base import BaseCommand
from kiharu_system.models import Institution

class Command(BaseCommand):
    help = "Seed Kenyan universities except Murang'a, Nairobi, Kenyatta, and MKU"

    def handle(self, *args, **kwargs):
        universities = [
            "Egerton University",
            "Jomo Kenyatta University of Agriculture and Technology (JKUAT)",
            "Moi University",
            "Technical University of Kenya (TUK)",
            "Maseno University",
            "Masinde Muliro University of Science and Technology (MMUST)",
            "Chuka University",
            "Dedan Kimathi University of Technology (DeKUT)",
            "Kisii University",
            "South Eastern Kenya University (SEKU)",
            "University of Eldoret",
            "Pwani University",
            "Karatina University",
            "Laikipia University",
            "Machakos University",
            "Meru University of Science and Technology",
            "Rongo University",
            "Embu University",
            "Maasai Mara University",
            "Taita Taveta University",
            "Kirinyaga University",
            "Tharaka University",
            "Alupe University College",
            "Garissa University",
            "Cooperative University of Kenya",
        ]

        excluded = [
            "Murang'a University of Technology",
            "University of Nairobi",
            "Kenyatta University",
            "Mount Kenya University"
        ]

        final_universities = [
            u for u in universities
            if all(ex.lower() not in u.lower() for ex in excluded)
        ]

        for uni in final_universities:
            obj, created = Institution.objects.get_or_create(
                name=uni,
                defaults={
                    "institution_type": "university",
                    "county": "Unknown",  # Change later if needed
                }
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f"✅ Added {uni}"))
            else:
                self.stdout.write(self.style.WARNING(f"ℹ️ Skipped {uni} (already exists)"))        
