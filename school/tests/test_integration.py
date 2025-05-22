import unittest
from school import create_app, db, bcrypt
from school.models import User, Student, ClassDetails

class StudentManagementIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.app, _, _, _, _, _ = create_app(testing=True)
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['WTF_CSRF_ENABLED'] = False
        self.app_context = self.app.app_context()
        self.app_context.push()
        self.client = self.app.test_client()
        db.create_all()
        
        # Create test admin user
        hashed_password = bcrypt.generate_password_hash('Admin123!').decode('utf-8')
        admin = User(username='admin', email='admin@example.com', 
                    user_role='Admin', password=hashed_password, is_approved=True)
        db.session.add(admin)
        db.session.commit()
        
        # Login
        self.client.post('/login', data={
            'email': 'admin@example.com',
            'password': 'Admin123!'
        })
        
    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()
        
    def test_student_full_workflow(self):
        """Test complete student workflow from creation to class details"""
        # 1. Create student
        response = self.client.post('/student_form', data={
            'pen_num': 12345,
            'admission_number': 54321,
            'aadhar_number': 123456789012,
            'student_name': 'Integration Test',
            'father_name': 'Integration Father',
            'mother_name': 'Integration Mother',
            'gender': 'Male',
            'date_of_birth': '2010-01-01',
            'date_of_joining': '2020-06-01',
            'contact_number': '9876543210',
            'village': 'Integration Village'
        }, follow_redirects=True)
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Student record added successfully', response.data)
        
        # 2. Add class details
        response = self.client.post('/class_details_form', data={
            'pen_num': 12345,
            'year': 2023,
            'current_class': 5,
            'section': 'A',
            'roll_number': 10,
            'photo_id': 123,
            'language': 'English',
            'vocational': 'None',
            'currently_enrolled': 'y'
        }, follow_redirects=True)
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Class details added successfully', response.data)
        
        # 3. Verify data
        student = Student.query.get(12345)
        self.assertEqual(student.student_name, 'Integration Test')
        
        class_details = ClassDetails.query.filter_by(pen_num=12345, year=2023).first()
        self.assertEqual(class_details.current_class, 5)
        self.assertEqual(class_details.section, 'A')
        
        # 4. Update student
        response = self.client.post('/student_form?edit_pen_num=12345', data={
            'pen_num': 12345,
            'admission_number': 54321,
            'aadhar_number': 123456789012,
            'student_name': 'Updated Integration Test',
            'father_name': 'Integration Father',
            'mother_name': 'Integration Mother',
            'gender': 'Male',
            'date_of_birth': '2010-01-01',
            'date_of_joining': '2020-06-01',
            'contact_number': '9876543210',
            'village': 'Integration Village'
        }, follow_redirects=True)
        
        self.assertIn(b'Student record updated successfully', response.data)
        
        # Verify update
        student = Student.query.get(12345)
        self.assertEqual(student.student_name, 'Updated Integration Test')
