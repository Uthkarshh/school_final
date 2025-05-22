import unittest
from datetime import date
from school import create_app
from school.models import parse_date_from_string
from school.routes import mask_aadhar, secure_save_file
import os
import tempfile
from werkzeug.datastructures import FileStorage

class UtilityTestCase(unittest.TestCase):
    def setUp(self):
        self.app, _, _, _, _, _ = create_app(testing=True)
        self.app_context = self.app.app_context()
        self.app_context.push()
        
    def tearDown(self):
        self.app_context.pop()
        
    def test_parse_date_from_string(self):
        """Test date parsing functionality"""
        # Test different date formats
        self.assertEqual(parse_date_from_string('2023-01-15'), date(2023, 1, 15))
        self.assertEqual(parse_date_from_string('15/01/2023'), date(2023, 1, 15))
        self.assertEqual(parse_date_from_string('01.15.2023'), date(2023, 1, 15))
        
        # Test with column name hints
        self.assertEqual(
            parse_date_from_string('15-01-2023', 'date_of_birth (dd-mm-yyyy)'), 
            date(2023, 1, 15)
        )
        
        # Test with already date object
        today = date.today()
        self.assertEqual(parse_date_from_string(today), today)
        
        # Test with empty input
        self.assertIsNone(parse_date_from_string(None))
        self.assertIsNone(parse_date_from_string(''))
        
    def test_mask_aadhar(self):
        """Test Aadhar number masking"""
        self.assertEqual(mask_aadhar(123456789012), 'XXXXXXXX9012')
        self.assertEqual(mask_aadhar(None), '')
        self.assertEqual(mask_aadhar(''), '')
        
    def test_secure_save_file(self):
        """Test secure file saving"""
        # Create a temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a test file
            test_content = b'test file content'
            test_file = tempfile.NamedTemporaryFile(suffix='.jpg', delete=False)
            test_file.write(test_content)
            test_file.close()
            
            # Create a FileStorage object
            with open(test_file.name, 'rb') as f:
                file_storage = FileStorage(
                    stream=f,
                    filename='test.jpg',
                    content_type='image/jpeg'
                )
                
                # Test saving valid file
                success, filename = secure_save_file(file_storage, temp_dir, max_size=1024*1024)
                self.assertTrue(success)
                self.assertTrue(os.path.exists(os.path.join(temp_dir, filename)))
                
            # Test with invalid extension
            with open(test_file.name, 'rb') as f:
                file_storage = FileStorage(
                    stream=f,
                    filename='test.exe',
                    content_type='application/octet-stream'
                )
                
                success, error_msg = secure_save_file(file_storage, temp_dir, max_size=1024*1024)
                self.assertFalse(success)
                self.assertIn('File type not allowed', error_msg)
                
            # Clean up
            os.unlink(test_file.name)
