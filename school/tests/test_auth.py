import unittest
from flask import url_for
from school import create_app, db, bcrypt
from school.models import User

class AuthTestCase(unittest.TestCase):
    def setUp(self):
        self.app, _, _, _, _, _ = create_app(testing=True)
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['WTF_CSRF_ENABLED'] = False
        self.app_context = self.app.app_context()
        self.app_context.push()
        self.client = self.app.test_client()
        db.create_all()
        
        # Create test user
        hashed_password = bcrypt.generate_password_hash('Password123!').decode('utf-8')
        user = User(username='testuser', email='test@example.com', 
                   user_role='Admin', password=hashed_password, is_approved=True)
        db.session.add(user)
        db.session.commit()
        
    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()
        
    def test_register_user(self):
        """Test user registration functionality"""
        response = self.client.post('/register', data={
            'username': 'newuser',
            'email': 'new@example.com',
            'user_role': 'Teacher',
            'password': 'TestPass123!',
            'confirm_password': 'TestPass123!'
        }, follow_redirects=True)
        
        self.assertEqual(response.status_code, 200)
        user = User.query.filter_by(email='new@example.com').first()
        self.assertIsNotNone(user)
        self.assertEqual(user.username, 'newuser')
        self.assertFalse(user.is_approved)
        
    def test_login_valid(self):
        """Test login with valid credentials"""
        response = self.client.post('/login', data={
            'email': 'test@example.com',
            'password': 'Password123!'
        }, follow_redirects=True)
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Dashboard', response.data)
        
    def test_login_invalid(self):
        """Test login with invalid credentials"""
        response = self.client.post('/login', data={
            'email': 'test@example.com',
            'password': 'WrongPassword123!'
        }, follow_redirects=True)
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Login unsuccessful', response.data)
        
    def test_logout(self):
        """Test logout functionality"""
        # First login
        self.client.post('/login', data={
            'email': 'test@example.com',
            'password': 'Password123!'
        })
        
        # Then logout
        response = self.client.get('/logout', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'You have been logged out', response.data)
        
    def test_account_lockout(self):
        """Test account lockout after multiple failed login attempts"""
        # Configure for testing
        self.app.config['MAX_LOGIN_ATTEMPTS'] = 3
        
        # Make 3 failed login attempts
        for _ in range(3):
            self.client.post('/login', data={
                'email': 'test@example.com',
                'password': 'WrongPassword123!'
            })
            
        # Check if account is locked
        response = self.client.post('/login', data={
            'email': 'test@example.com',
            'password': 'Password123!'  # Correct password
        }, follow_redirects=True)
        
        self.assertIn(b'Your account has been locked', response.data)
