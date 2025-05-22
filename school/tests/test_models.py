import unittest
from datetime import date
from school import create_app, db
from school.models import Student, User, Fee, FeeBreakdown, Transport

class ModelValidationTestCase(unittest.TestCase):
    def setUp(self):
        self.app, _, _, _, _, _ = create_app(testing=True)
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        
    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()
        
    def test_student_validation(self):
        """Test Student model validation"""
        # Valid student
        valid_student = Student(
            pen_num=12345,
            admission_number=54321,
            aadhar_number=123456789012,
            student_name='Test Student',
            father_name='Father Name',
            mother_name='Mother Name',
            gender='Male',
            date_of_birth=date(2010, 1, 1),
            date_of_joining=date(2020, 6, 1),
            contact_number='9876543210',
            village='Test Village',
            created_by='admin'
        )
        db.session.add(valid_student)
        db.session.commit()
        
        self.assertEqual(Student.query.count(), 1)
        
        # Invalid aadhar number (not 12 digits)
        invalid_student = Student(
            pen_num=12346,
            admission_number=54322,
            aadhar_number=12345,  # Too short
            student_name='Invalid Student',
            father_name='Father Name',
            mother_name='Mother Name',
            gender='Male',
            date_of_birth=date(2010, 1, 1),
            date_of_joining=date(2020, 6, 1),
            contact_number='9876543210',
            village='Test Village',
            created_by='admin'
        )
        
        with self.assertRaises(ValueError):
            db.session.add(invalid_student)
            db.session.commit()
            
        db.session.rollback()
        
        # Invalid gender
        invalid_student = Student(
            pen_num=12346,
            admission_number=54322,
            aadhar_number=123456789013,
            student_name='Invalid Student',
            father_name='Father Name',
            mother_name='Mother Name',
            gender='InvalidGender',  # Invalid gender
            date_of_birth=date(2010, 1, 1),
            date_of_joining=date(2020, 6, 1),
            contact_number='9876543210',
            village='Test Village',
            created_by='admin'
        )
        
        with self.assertRaises(ValueError):
            db.session.add(invalid_student)
            db.session.commit()
            
    def test_fee_concession_calculation(self):
        """Test Fee concession calculation"""
        # Staff concession (50%)
        staff_fee = Fee(
            pen_num=1,
            year=2023,
            school_fee=50000,
            concession_reason='Staff',
            transport_used=False,
            application_fee=1000,
            created_by='admin'
        )
        db.session.add(staff_fee)
        db.session.commit()
        
        self.assertEqual(staff_fee.school_fee_concession, 25000)  # 50% of 50000
        
        # Sibling concession (10%)
        sibling_fee = Fee(
            pen_num=2,
            year=2023,
            school_fee=50000,
            concession_reason='Sibling',
            transport_used=False,
            application_fee=1000,
            created_by='admin'
        )
        db.session.add(sibling_fee)
        db.session.commit()
        
        self.assertEqual(sibling_fee.school_fee_concession, 5000)  # 10% of 50000
