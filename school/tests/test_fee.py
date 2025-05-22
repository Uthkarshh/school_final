import unittest
from decimal import Decimal
from datetime import date
from school import create_app, db
from school.models import User, Student, Fee, FeeBreakdown, Transport

class FeeTestCase(unittest.TestCase):
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
        
        # Create test student
        student = Student(
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
        db.session.add(student)
        
        # Create transport route
        transport = Transport(
            pick_up_point='Test Point',
            route_number=1,
            created_by='admin'
        )
        db.session.add(transport)
        
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
        
    def test_create_fee_record(self):
        """Test creating a new fee record"""
        response = self.client.post('/fee_form', data={
            'pen_num': 12345,
            'year': 2023,
            'school_fee': 50000,
            'concession_reason': 'Staff',
            'transport_used': 'y',
            'application_fee': 1000,
            'transport_fee': 10000,
            'transport_fee_concession': 0,
            'pick_up_point': 'Test Point'
        }, follow_redirects=True)
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Fee record added successfully', response.data)
        
        fee_record = Fee.query.filter_by(pen_num=12345, year=2023).first()
        self.assertIsNotNone(fee_record)
        self.assertEqual(fee_record.school_fee, 50000)
        self.assertEqual(fee_record.school_fee_concession, 25000)  # 50% of 50000 for Staff
        self.assertTrue(fee_record.transport_used)
        
    def test_add_fee_payment(self):
        """Test adding a fee payment"""
        # First create a fee record
        fee = Fee(
            pen_num=12345,
            year=2023,
            school_fee=50000,
            concession_reason='Staff',
            school_fee_concession=25000,
            transport_used=False,
            application_fee=1000,
            created_by='admin'
        )
        db.session.add(fee)
        db.session.commit()
        
        # Add a fee payment
        response = self.client.post('/fee_breakdown_form', data={
            'pen_num': 12345,
            'year': 2023,
            'fee_type': 'School',
            'term': 'Q1',
            'payment_type': 'Cash',
            'paid': 8000,
            'receipt_no': 101,
            'fee_paid_date': date.today().strftime('%Y-%m-%d')
        }, follow_redirects=True)
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Fee breakdown added successfully', response.data)
        
        payment = FeeBreakdown.query.filter_by(
            pen_num=12345, year=2023, fee_type='School', term='Q1'
        ).first()
        self.assertIsNotNone(payment)
        self.assertEqual(float(payment.paid), 8000.0)
