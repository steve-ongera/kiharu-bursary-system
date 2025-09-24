from django.core.management.base import BaseCommand
from kiharu_system.models import Institution

class Command(BaseCommand):
    help = "Seed Kenyan colleges, including all KMTC campuses and other national colleges"

    def handle(self, *args, **kwargs):
        colleges = [
            # --- KMTC Main and Campuses ---
            "Kenya Medical Training College (KMTC) Nairobi",
            "KMTC Kisumu",
            "KMTC Mombasa",
            "KMTC Nakuru",
            "KMTC Machakos",
            "KMTC Nyeri",
            "KMTC Kakamega",
            "KMTC Embu",
            "KMTC Kitui",
            "KMTC Thika",
            "KMTC Siaya",
            "KMTC Kisii",
            "KMTC Garissa",
            "KMTC Kapkatet",
            "KMTC Lodwar",
            "KMTC Kilifi",
            "KMTC Vihiga",
            "KMTC Meru",
            "KMTC Homa Bay",
            "KMTC Chuka",
            "KMTC Migori",
            "KMTC Kabarnet",
            "KMTC Othaya",
            "KMTC Wajir",
            "KMTC Msambweni",
            "KMTC Busia",
            "KMTC Bomet",
            "KMTC Iten",
            "KMTC Kitale",
            "KMTC Loitoktok",
            "KMTC Mutomo",
            "KMTC Taveta",
            "KMTC Tana River",
            "KMTC Kericho",
            "KMTC Nyamira",
            "KMTC Mathari",
            "KMTC Lamu",
            "KMTC Nyahururu",
            "KMTC Bondo",
            "KMTC Makueni",
            "KMTC Kajiado",
            "KMTC Kwale",
            "KMTC Kuria",
            "KMTC Turkana",
            # --- Other national colleges ---
            "Kenya Institute of Mass Communication (KIMC)",
            "Kenya Technical Trainers College (KTTC)",
            "Kenya Utalii College",
            "Railway Training Institute",
            "Kenya Institute of Management (KIM)",
            "Kenya Institute of Professional Studies (KIPS)",
            "East Africa Institute of Certified Studies (ICS)",
            "Nairobi Technical Training Institute (NTTI)",
            "Kabete National Polytechnic",
            "Sigalagala National Polytechnic",
            "Rift Valley Technical Training Institute (RVTTI)",
            "Eldoret National Polytechnic",
            "Mombasa Technical Training Institute",
            "Kiambu Institute of Science and Technology (KIST)",
            "Thika Technical Training Institute",
            "Meru National Polytechnic",
            "Nyeri National Polytechnic",
            "Kisumu National Polytechnic",
            "Kitale National Polytechnic",
            "Maasai Technical Training Institute",
            "Karen Technical Training Institute for the Deaf",
            "Michuki Technical Training Institute",
            "Othaya Technical Training Institute",
        ]

        for college in colleges:
            obj, created = Institution.objects.get_or_create(
                name=college,
                defaults={
                    "institution_type": "college",
                    "county": "Unknown"  # Replace with real county mapping if needed
                }
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f"✅ Added {college}"))
            else:
                self.stdout.write(self.style.WARNING(f"ℹ️ Skipped {college} (already exists)"))
