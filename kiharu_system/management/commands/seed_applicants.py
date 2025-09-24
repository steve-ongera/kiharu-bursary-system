import random
import datetime
from django.core.management.base import BaseCommand
from django.contrib.auth.hashers import make_password
from kiharu_system.models import User, Applicant, Guardian, SiblingInformation, Institution, Ward, Location, SubLocation, Village

class Command(BaseCommand):
    help = "Seed Applicants with User, Guardian, and Sibling data"

    male_first_names = [
        "Brian", "Caleb", "Daniel", "Elijah", "Felix", "George", "Isaac", "Jacob",
        "Kevin", "Leonard", "Michael", "Nicholas", "Oscar", "Patrick", "Richard",
        "Samuel", "Thomas", "Victor", "William", "Yusuf", "David", "John", "James",
        "Robert", "Joseph", "Charles", "Paul", "Mark", "Stephen", "Andrew",
        "Philip", "Simon", "Peter", "Luke", "Matthew", "Timothy", "Anthony",
        "Benjamin", "Jonathan", "Joshua", "Aaron", "Adam", "Alexander", "Christopher",
        "Dennis", "Edwin", "Eric", "Francis", "Gabriel", "Henry", "Ian", "Kenneth",
        "Martin", "Nathan", "Peter", "Raphael", "Solomon", "Tony", "Vincent", "Zachary",
        "Ahmed", "Ali", "Mohamed", "Hassan", "Omar", "Abdullah", "Abdul", "Khalid",
        "Jamal", "Mustafa", "Ibrahim", "Idris", "Jabir", "Kamau", "Kipchoge", "Lemayan",
        "Mwangi", "Njoroge", "Odhiambo", "Omondi", "Otieno", "Waweru", "Kiprop", "Kiplagat"
    ]

    female_first_names = [
        "Abigail", "Brenda", "Catherine", "Diana", "Esther", "Faith", "Grace", "Hannah",
        "Irene", "Janet", "Lucy", "Mary", "Naomi", "Olivia", "Patricia", "Ruth",
        "Sarah", "Terry", "Valerie", "Winnie", "Alice", "Ann", "Beatrice", "Caroline",
        "Christine", "Dorcas", "Elizabeth", "Eunice", "Florence", "Gladys", "Joyce",
        "Judith", "Jane", "Joy", "Karen", "Lilian", "Margaret", "Mercy", "Nancy",
        "Pamela", "Rachel", "Rebecca", "Rose", "Sandra", "Susan", "Tabitha", "Veronica",
        "Wanjiru", "Agnes", "Angela", "Betty", "Cynthia", "Deborah", "Edith", "Eva",
        "Fiona", "Gloria", "Helen", "Jackline", "Lydia", "Martha", "Monica", "Nelly",
        "Pauline", "Priscilla", "Queenie", "Rita", "Salome", "Teresa", "Umazi", "Vivian",
        "Wairimu", "Zipporah", "Amina", "Fatuma", "Halima", "Khadija", "Mariam", "Nasra",
        "Sadia", "Zainab", "Chebet", "Chepkoech", "Jebet", "Jerono", "Korir", "Lagat"
    ]

    last_names = [
        "Ochieng", "Odhiambo", "Omondi", "Otieno", "Mutua", "Mwangi", "Wambui",
        "Kamau", "Njoroge", "Chebet", "Kiptoo", "Koech", "Cherono", "Kiplangat",
        "Kibaki", "Barasa", "Were", "Okoth", "Nyaga", "Ongera", "Maina", "Kariuki",
        "Kimani", "Ndungu", "Nyong'o", "Wafula", "Simiyu", "Musyoka", "Kilonzo",
        "Muli", "Kinyua", "Gachara", "Thiong'o", "Wanyonyi", "Kipchumba", "Rotich",
        "Kemei", "Korir", "Langat", "Maritim", "Too", "Kosgei", "Kiprop", "Kiplimo",
        "Kipruto", "Kipkosgei", "Kipngetich", "Kiprono", "Kipsang", "Kipserem",
        "Kandie", "Kipkemboi", "Kipkurui", "Kipyego", "Komen", "Kip", "Kibet",
        "Kibiwott", "Kiptanui", "Kiptere", "Kipngeno", "Kipchirchir", "Kipkoech",
        "Kipketer", "Kiprotich", "Kipsang", "Kipyego", "Korir", "Koskei", "Kurgat",
        "Kutai", "Kwambai", "Lagat", "Limo", "Longosiwa", "Loroupe", "Maritim",
        "Masai", "Mate", "Mogusu", "Mosop", "Mosoti", "Muchiri", "Mungara", "Munyo",
        "Murimi", "Musyoki", "Mutai", "Mutiso", "Mutwiri", "Mwaniki", "Mwangi",
        "Ndiwa", "Ndungu", "Ngugi", "Njenga", "Njeri", "Njogu", "Njoroge", "Ngetich",
        "Nyakundi", "Nyong'o", "Obare", "Odero", "Ogola", "Ojwang", "Okello", "Okumu",
        "Olouch", "Omondi", "Onyango", "Opicho", "Opiyo", "Opondo", "Osoro", "Otieno",
        "Ouma", "Outa", "Owino", "Oyugi", "Samoei", "Sang", "Simotwo", "Simiyu",
        "Soi", "Sum", "Tanui", "Tarbei", "Tergat", "Tirop", "Tuitoek", "Tum",
        "Wachira", "Wafula", "Wairimu", "Wambua", "Wanjiku", "Wanjiru", "Wanyonyi",
        "Were", "Yator", "Yego", "Khalif", "Mohamed", "Abdi", "Abdullahi", "Ali",
        "Hassan", "Ibrahim", "Omar", "Osman", "Sheikh", "Warsame", "Duale", "Farah"
    ]
    
    guardian_names = [
        "Peter", "John", "Joseph", "James", "David", "Paul", "Charles", "Robert",
        "Elizabeth", "Margaret", "Susan", "Anne", "Beatrice", "Florence", "Eunice",
        
        # Male Guardians - Common Kenyan Names
        "Samuel", "Thomas", "Michael", "Daniel", "Stephen", "Andrew", "Philip", "Simon",
        "Mark", "Luke", "Matthew", "Timothy", "Anthony", "Benjamin", "Jonathan",
        "Joshua", "Aaron", "Adam", "Christopher", "Dennis", "Edwin", "Eric", "Francis",
        "Gabriel", "Henry", "Ian", "Kenneth", "Martin", "Nathan", "Raphael", "Solomon",
        "Tony", "Vincent", "Zachary", "Victor", "William", "Brian", "Caleb", "Elijah",
        "Felix", "George", "Isaac", "Jacob", "Kevin", "Leonard", "Nicholas", "Oscar",
        "Patrick", "Richard", "Yusuf",
        
        # Female Guardians - Common Kenyan Names
        "Mary", "Grace", "Hannah", "Irene", "Janet", "Lucy", "Naomi", "Olivia", "Patricia",
        "Ruth", "Sarah", "Terry", "Valerie", "Winnie", "Abigail", "Brenda", "Catherine",
        "Diana", "Esther", "Faith", "Alice", "Ann", "Caroline", "Christine", "Dorcas",
        "Gladys", "Joyce", "Judith", "Jane", "Joy", "Karen", "Lilian", "Mercy", "Nancy",
        "Pamela", "Rachel", "Rebecca", "Rose", "Sandra", "Tabitha", "Veronica", "Agnes",
        "Angela", "Betty", "Cynthia", "Deborah", "Edith", "Eva", "Fiona", "Gloria",
        "Helen", "Jackline", "Lydia", "Martha", "Monica", "Nelly", "Pauline", "Priscilla",
        "Queenie", "Rita", "Salome", "Teresa", "Umazi", "Vivian", "Zipporah",
        
        # Kenyan Traditional Names (Male)
        "Kamau", "Mwangi", "Njoroge", "Odhiambo", "Omondi", "Otieno", "Ochieng", "Maina",
        "Kariuki", "Kimani", "Ndungu", "Wafula", "Simiyu", "Musyoka", "Kilonzo", "Kinyua",
        "Thiong'o", "Wanyonyi", "Kipchumba", "Rotich", "Korir", "Langat", "Kiprop",
        "Kiplimo", "Kipruto", "Kipsang", "Kibet", "Kandie", "Komen", "Kibiwott",
        
        # Kenyan Traditional Names (Female)
        "Wanjiru", "Wambui", "Nyokabi", "Wairimu", "Njeri", "Wanjiku", "Akinyi", "Atieno",
        "Aoko", "Awuor", "Adhiambo", "Anyango", "Apiyo", "Chelangat", "Chepkoech", "Chebet",
        "Jebet", "Jerono", "Korir", "Lagat", "Chepngetich", "Chepchumba", "Cherotich",
        
        # Muslim Guardian Names (Male)
        "Ahmed", "Ali", "Mohamed", "Hassan", "Omar", "Abdullah", "Abdul", "Khalid",
        "Jamal", "Mustafa", "Ibrahim", "Idris", "Jabir", "Farah", "Abdi", "Osman",
        "Sheikh", "Duale", "Warsame", "Khalif",
        
        # Muslim Guardian Names (Female)
        "Amina", "Fatuma", "Halima", "Khadija", "Mariam", "Nasra", "Sadia", "Zainab",
        "Asha", "Fardosa", "Habiba", "Hodan", "Iman", "Leyla", "Muna", "Naima",
        "Samira", "Sofia", "Warsan", "Yasmin",
        
        # Elder/Respectful Titles (Common for Guardians)
        "Mzee", "Baba", "Mama", "Daktari", "Prof", "Engineer", "Teacher", "Pastor",
        "Reverend", "Father", "Sister", "Brother", "Captain", "Chief", "Councillor",
        
        # Combined Names (Common in Kenyan Context)
        "John Maina", "Mary Wambui", "Peter Kamau", "Elizabeth Wanjiru",
        "Joseph Odhiambo", "Grace Nyokabi", "David Kariuki", "Sarah Njeri",
        "James Mwangi", "Margaret Wairimu", "Paul Omondi", "Susan Akinyi",
        "Samuel Otieno", "Lucy Adhiambo", "Daniel Kipchumba", "Hannah Chebet",
        "Michael Korir", "Irene Chepkoech", "Thomas Kibet", "Naomi Chelangat",
        
        # Professional Titles
        "Dr. Kimani", "Prof. Odhiambo", "Eng. Maina", "Rev. Waweru", "Fr. Omondi",
        "Sr. Margaret", "Mr. Otieno", "Mrs. Wanjiku", "Ms. Akinyi", "Madam Wambui",
        
        # Common Guardian Name Combinations
        "Baba John", "Mama Mary", "Mzee Samuel", "Dada Elizabeth", "Kaka Joseph",
        "Shosh Beatrice", "Guka Florence", "Babu Peter", "Nyanya Anne"
    ]

    def handle(self, *args, **kwargs):
        wards = list(Ward.objects.all())
        locations = list(Location.objects.all())
        sublocations = list(SubLocation.objects.all())
        villages = list(Village.objects.all())

        if not wards or not locations or not sublocations or not villages:
            self.stdout.write(self.style.ERROR("❌ Please seed Ward/Location/SubLocation/Village first."))
            return

        institutions = Institution.objects.all()
        total_created = 0

        for institution in institutions:
            num_applicants = random.randint(3, 8)
            self.stdout.write(self.style.WARNING(f"Seeding {num_applicants} applicants for {institution.name}..."))

            for i in range(num_applicants):
                gender = random.choice(["M", "F"])
                if gender == "M":
                    first_name = random.choice(self.male_first_names)
                else:
                    first_name = random.choice(self.female_first_names)

                last_name = random.choice(self.last_names)
                username = f"{first_name.lower()}{last_name.lower()}{random.randint(100,999)}"
                email = f"{first_name.lower()}.{last_name.lower()}@gmail.com"
                phone_number = f"+2547{random.randint(10000000, 99999999)}"
                id_number = str(random.randint(10000000, 99999999))

                # Create user
                user = User.objects.create(
                    username=username,
                    first_name=first_name,
                    last_name=last_name,
                    email=email,
                    user_type="applicant",
                    id_number=id_number,
                    phone_number=phone_number,
                    password=make_password("password123"),
                )

                # Create applicant
                applicant = Applicant.objects.create(
                    user=user,
                    gender=gender,
                    date_of_birth=datetime.date(
                        random.randint(1995, 2006),
                        random.randint(1, 12),
                        random.randint(1, 28),
                    ),
                    id_number=id_number,
                    ward=random.choice(wards),
                    location=random.choice(locations),
                    sublocation=random.choice(sublocations),
                    village=random.choice(villages),
                    physical_address=f"House {random.randint(1,500)}, P.O Box {random.randint(100,999)}",
                    postal_address=f"P.O Box {random.randint(100,999)}-00{random.randint(100,999)}",
                )

                # Create guardians
                father_name = random.choice(self.guardian_names) + " " + last_name
                mother_name = random.choice(self.guardian_names) + " " + last_name
                Guardian.objects.create(
                    applicant=applicant,
                    name=father_name,
                    relationship="father",
                    phone_number=f"+2547{random.randint(10000000, 99999999)}",
                    occupation="Farmer",
                    monthly_income=random.randint(10000, 50000),
                    id_number=str(random.randint(10000000, 99999999))
                )
                Guardian.objects.create(
                    applicant=applicant,
                    name=mother_name,
                    relationship="mother",
                    phone_number=f"+2547{random.randint(10000000, 99999999)}",
                    occupation="Business",
                    monthly_income=random.randint(5000, 40000),
                    id_number=str(random.randint(10000000, 99999999))
                )

                # Create siblings (2–4)
                for s in range(random.randint(2, 4)):
                    sibling_name = random.choice(self.male_first_names + self.female_first_names) + " " + last_name
                    SiblingInformation.objects.create(
                        applicant=applicant,
                        name=sibling_name,
                        age=random.randint(5, 22),
                        education_level=random.choice(["Primary", "Secondary", "College", "University"]),
                        school_name=random.choice([
                            "Kakamega High", "Alliance Girls", "Maseno School",
                            "Moi University", "University of Nairobi", "Nakuru High",
                            "Egerton University", "Strathmore University"
                        ])
                    )

                total_created += 1
                self.stdout.write(self.style.SUCCESS(f"✅ Created applicant {first_name} {last_name}"))

        self.stdout.write(self.style.SUCCESS(f"🎉 Done! Seeded {total_created} applicants across {institutions.count()} institutions."))
