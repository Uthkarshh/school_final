import unittest
from datetime import date
from school import create_app, db
from school.models import Student, User

class StudentTestCase(unittest.TestCase):
    def setUp(self):
        self.app, _, _, _, _, _ = create_app(testing=True)
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['WTF_CSRF_ENABLED'] = False
        self.app_context = self.app.app_context()
        self.app_context.push()
        self.client = self.app.test_client()
        db.create_all()
        
        # Create admin user
        admin_user = User(username='admin', email='admin@example.com', 
                         user_role='Admin', password='hashed_password', is_approved=True)
        db.session.add(admin_user)
        db.session.commit()
        
        # Login the admin user
        self.client.post('/login', data={
            'email': 'admin@example.com',
            'password': 'hashed_password'
        })
        
    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()
        
    def test_create_student(self):
        """Test creating a new student record"""
        response = self.client.post('/student_form', data={
            'pen_num': 12345,
            'admission_number': 54321,
            'aadhar_number': 123456789012,
            'student_name': 'Test Student',
            'father_name': 'Test Father',
            'mother_name': 'Test Mother',
            'gender': 'Male',
            'date_of_birth': '2010-01-01',
            'date_of_joining': '2020-06-01',
            'contact_number': '9876543210',
            'village': 'Test Village'
        }, follow_redirects=True)
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Student record added successfully', response.data)
        
        student = Student.query.get(12345)
        self.assertIsNotNone(student)
        self.assertEqual(student.student_name, 'Test Student')
        
    def test_update_student(self):
        """Test updating an existing student record"""
        # First create a student
        student = Student(
            pen_num=12345,
            admission_number=54321,
            aadhar_number=123456789012,
            student_name='Original Name',
            father_name='Father Name',
            mother_name='Mother Name',
            gender='Male',
            date_of_birth=date(2010, 1, 1),
            date_of_joining=date(2020, 6, 1),
            contact_number='9876543210',
            village='Original Village',
            created_by='admin'
        )
        db.session.add(student)
        db.session.commit()
        
        # Update the student
        response = self.client.post('/student_form?edit_pen_num=12345', data={
            'pen_num': 12345,
            'admission_number': 54321,
            'aadhar_number': 123456789012,
            'student_name': 'Updated Name',
            'father_name': 'Father Name',
            'mother_name': 'Mother Name',
            'gender': 'Male',
            'date_of_birth': '2010-01-01',
            'date_of_joining': '2020-06-01',
            'contact_number': '9876543210',
            'village': 'Updated Village'
        }, follow_redirects=True)
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Student record updated successfully', response.data)
        
        student = Student.query.get(12345)
        self.assertEqual(student.student_name, 'Updated Name')
        self.assertEqual(student.village, 'Updated Village')
