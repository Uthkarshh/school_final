"""
Forms module for the school fee management application.

This module defines all the forms used in the application, including user registration,
authentication, student information, fee details, and more.
"""

import logging
import os
import re
from datetime import date, datetime
from typing import Any, Optional

from flask import current_app
from flask_login import current_user
from flask_wtf import FlaskForm, RecaptchaField
from flask_wtf.file import FileAllowed, FileField, FileSize
from wtforms import (BooleanField, DateField, DecimalField, IntegerField,
                     PasswordField, SelectField, StringField, SubmitField,
                     TextAreaField)
from wtforms.validators import (DataRequired, Email, EqualTo, InputRequired,
                               Length, NumberRange, Optional, Regexp,
                               ValidationError)

from school.models import Fee, Student, Transport, User

# Set up logging
logger = logging.getLogger(__name__)

# Load configuration from environment
MAX_UPLOAD_SIZE = int(os.environ.get('MAX_UPLOAD_SIZE', 5 * 1024 * 1024))  # 5MB default
RECAPTCHA_ENABLED = os.environ.get('RECAPTCHA_ENABLED', 'False').lower() == 'true'
MIN_PASSWORD_LENGTH = int(os.environ.get('MIN_PASSWORD_LENGTH', 8))


def sanitize_string(value: str) -> str:
    """Sanitize a string input by removing dangerous characters.
    
    Args:
        value: The string to sanitize
        
    Returns:
        Sanitized string
    """
    if not value:
        return value
    # Remove potentially dangerous HTML/script tags
    value = re.sub(r'<[^>]*>', '', value)
    # Remove common SQL injection patterns
    value = re.sub(r'(\b)(on\S+)(\s*)=|javascript:|(<\s*)(\/*)script', '', value, flags=re.IGNORECASE)
    return value.strip()


class PasswordComplexityValidator:
    """Validator for password complexity requirements."""
    
    def __init__(self, message=None):
        """Initialize the validator.
        
        Args:
            message: Custom error message
        """
        self.message = message or (
            'Password must contain at least one uppercase letter, '
            'one lowercase letter, one number, and one special character'
        )
    
    def __call__(self, form: FlaskForm, field: Any) -> None:
        """Validate password complexity.
        
        Args:
            form: The form containing the field
            field: The password field to validate
            
        Raises:
            ValidationError: If the password doesn't meet complexity requirements
        """
        password = field.data
        
        # Check for password complexity
        if not re.search(r'[A-Z]', password):
            raise ValidationError('Password must contain at least one uppercase letter')
        
        if not re.search(r'[a-z]', password):
            raise ValidationError('Password must contain at least one lowercase letter')
        
        if not re.search(r'[0-9]', password):
            raise ValidationError('Password must contain at least one number')
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValidationError('Password must contain at least one special character')


class BaseForm(FlaskForm):
    """Base form class with common functionality."""
    
    class Meta:
        """Meta configuration for all forms."""
        csrf = True
        csrf_time_limit = 3600  # 1 hour
    
    def process_data(self) -> None:
        """Process and sanitize form data."""
        for field in self:
            if isinstance(field.data, str) and not isinstance(field, PasswordField):
                field.data = sanitize_string(field.data)


class RegistrationForm(BaseForm):
    """Form for user registration."""
    
    username = StringField(
        'Username', 
        validators=[
            DataRequired(message="Username is required"),
            Length(min=2, max=20, message="Username must be between 2 and 20 characters"),
            Regexp(r'^[a-zA-Z0-9_]+$', message="Username can only contain letters, numbers, and underscores")
        ],
        description="Choose a unique username (2-20 characters, letters, numbers, underscores only)"
    )
    
    email = StringField(
        'Email', 
        validators=[
            DataRequired(message="Email is required"),
            Email(message="Please enter a valid email address"),
        ],
        description="Enter your email address (will be used for login and password recovery)"
    )
    
    user_role = SelectField(
        'User Role', 
        choices=[
            ('Admin', 'Administrator'), 
            ('Teacher', 'Teacher'), 
            ('Staff', 'Staff'),
            ('Accountant', 'Accountant')
        ],
        validators=[DataRequired(message="User role is required")],
        description="Select your role in the school"
    )
    
    password = PasswordField(
        'Password', 
        validators=[
            DataRequired(message="Password is required"),
            Length(min=MIN_PASSWORD_LENGTH, message=f"Password must be at least {MIN_PASSWORD_LENGTH} characters long"),
            PasswordComplexityValidator()
        ],
        description=f"Create a secure password (min {MIN_PASSWORD_LENGTH} characters with uppercase, lowercase, numbers, symbols)"
    )
    
    confirm_password = PasswordField(
        'Confirm Password', 
        validators=[
            DataRequired(message="Please confirm your password"),
            EqualTo('password', message="Passwords must match")
        ],
        description="Re-enter your password to confirm"
    )
    
    # Add reCAPTCHA if enabled
    if RECAPTCHA_ENABLED:
        recaptcha = RecaptchaField()
    
    submit = SubmitField('Sign Up')

    def validate_username(self, username: StringField) -> None:
        """Validate username is unique.
        
        Args:
            username: The username field to validate
            
        Raises:
            ValidationError: If the username is already taken
        """
        user = User.query.filter_by(username=username.data).first()
        if user:
            logger.warning(f"Registration attempt with existing username: {username.data}")
            raise ValidationError('That username is taken. Please choose a different one')
        
    def validate_email(self, email: StringField) -> None:
        """Validate email is unique.
        
        Args:
            email: The email field to validate
            
        Raises:
            ValidationError: If the email is already registered
        """
        user = User.query.filter_by(email=email.data).first()
        if user:
            logger.warning(f"Registration attempt with existing email: {email.data}")
            raise ValidationError('That email is already registered. Please choose a different one or reset your password')


class LoginForm(BaseForm):
    """Form for user login."""
    
    email = StringField(
        'Email', 
        validators=[
            DataRequired(message="Email is required"),
            Email(message="Please enter a valid email address")
        ],
        description="Enter your registered email address"
    )
    
    password = PasswordField(
        'Password', 
        validators=[
            DataRequired(message="Password is required")
        ],
        description="Enter your password"
    )
    
    remember = BooleanField(
        'Remember Me',
        description="Keep me logged in on this device (not recommended for shared computers)"
    )
    
    # Add reCAPTCHA if enabled
    if RECAPTCHA_ENABLED:
        recaptcha = RecaptchaField()
    
    submit = SubmitField('Login')


class UpdateAccountForm(BaseForm):
    """Form for updating user account information."""
    
    username = StringField(
        'Username', 
        validators=[
            DataRequired(message="Username is required"),
            Length(min=2, max=20, message="Username must be between 2 and 20 characters"),
            Regexp(r'^[a-zA-Z0-9_]+$', message="Username can only contain letters, numbers, and underscores")
        ],
        description="Update your username (2-20 characters, letters, numbers, underscores only)"
    )
    
    email = StringField(
        'Email', 
        validators=[
            DataRequired(message="Email is required"),
            Email(message="Please enter a valid email address")
        ],
        description="Update your email address"
    )
    
    picture = FileField(
        'Update Profile Picture', 
        validators=[
            FileAllowed(['jpg', 'jpeg', 'png'], message="Only JPG and PNG images are allowed"),
            FileSize(max_size=MAX_UPLOAD_SIZE, message=f"File size must be less than {MAX_UPLOAD_SIZE/1024/1024:.1f}MB")
        ],
        description="Upload a profile picture (JPG/PNG only, max 5MB)"
    )
    
    current_password = PasswordField(
        'Current Password',
        validators=[Optional()],
        description="Enter your current password to confirm changes"
    )
    
    submit = SubmitField('Update')

    def validate_username(self, username: StringField) -> None:
        """Validate username is unique (excluding current user).
        
        Args:
            username: The username field to validate
            
        Raises:
            ValidationError: If the username is already taken by another user
        """
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                logger.warning(f"Account update attempt with existing username: {username.data}")
                raise ValidationError('That username is taken. Please choose a different one')
        
    def validate_email(self, email: StringField) -> None:
        """Validate email is unique (excluding current user).
        
        Args:
            email: The email field to validate
            
        Raises:
            ValidationError: If the email is already registered to another user
        """
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                logger.warning(f"Account update attempt with existing email: {email.data}")
                raise ValidationError('That email is already registered. Please choose a different one')
            
            
class StudentForm(BaseForm):
    """Form for student information."""
    
    pen_num = IntegerField(
        'PEN Number', 
        validators=[
            DataRequired(message="PEN Number is required"),
            NumberRange(min=1, message="PEN Number must be a positive integer")
        ],
        description="Permanent Enrollment Number (unique identifier)"
    )
    
    admission_number = IntegerField(
        'Admission Number', 
        validators=[
            DataRequired(message="Admission Number is required"),
            NumberRange(min=1, message="Admission Number must be a positive integer")
        ],
        description="School admission number"
    )
    
    aadhar_number = IntegerField(
        'Aadhar Number', 
        validators=[
            DataRequired(message="Aadhar Number is required")
        ],
        description="12-digit government ID number"
    )
    
    student_name = StringField(
        'Student Name', 
        validators=[
            DataRequired(message="Student Name is required"),
            Length(max=60, message="Student Name must be less than 60 characters"),
            Regexp(r'^[a-zA-Z\s.-]+$', message="Student Name can only contain letters, spaces, periods, and hyphens")
        ],
        description="Full name of student"
    )
    
    father_name = StringField(
        'Father Name', 
        validators=[
            DataRequired(message="Father's Name is required"),
            Length(max=60, message="Father's Name must be less than 60 characters"),
            Regexp(r'^[a-zA-Z\s.-]+$', message="Father's Name can only contain letters, spaces, periods, and hyphens")
        ],
        description="Father's full name"
    )
    
    mother_name = StringField(
        'Mother Name', 
        validators=[
            DataRequired(message="Mother's Name is required"),
            Length(max=60, message="Mother's Name must be less than 60 characters"),
            Regexp(r'^[a-zA-Z\s.-]+$', message="Mother's Name can only contain letters, spaces, periods, and hyphens")
        ],
        description="Mother's full name"
    )
    
    gender = SelectField(
        'Gender', 
        choices=[('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')], 
        validators=[DataRequired(message="Gender is required")],
        description="Student's gender"
    )
    
    date_of_birth = DateField(
        'Date of Birth', 
        validators=[DataRequired(message="Date of Birth is required")],
        description="Student's date of birth (YYYY-MM-DD)"
    )
    
    date_of_joining = DateField(
        'Date of Joining', 
        validators=[DataRequired(message="Date of Joining is required")],
        description="Date when student joined the school (YYYY-MM-DD)"
    )
    
    contact_number = StringField(
        'Contact Number', 
        validators=[
            DataRequired(message="Contact Number is required"),
            Length(max=20, message="Contact Number must be less than 20 characters"),
            Regexp(r'^[0-9+\-\s()]+$', message="Contact Number can only contain digits, +, -, spaces, and parentheses")
        ],
        description="Parent/guardian contact number"
    )
    
    village = StringField(
        'Village/Area', 
        validators=[
            DataRequired(message="Village/Area is required"),
            Length(max=50, message="Village/Area must be less than 50 characters")
        ],
        description="Village or residential area"
    )
    
    submit = SubmitField('Save')

    def validate_date_of_birth(self, field: DateField) -> None:
        """Ensure student is of reasonable age.
        
        Args:
            field: The date_of_birth field to validate
            
        Raises:
            ValidationError: If the student's age is not between 3 and 30 years
        """
        if field.data:
            today = date.today()
            age = today.year - field.data.year - ((today.month, today.day) < (field.data.month, field.data.day))
            if age < 3 or age > 30:
                raise ValidationError('Please enter a valid date of birth (age 3-30)')
                
            # Also check that the date is not in the future
            if field.data > today:
                raise ValidationError('Date of birth cannot be in the future')
    
    def validate_date_of_joining(self, field: DateField) -> None:
        """Ensure date of joining is valid.
        
        Args:
            field: The date_of_joining field to validate
            
        Raises:
            ValidationError: If the date is invalid (future or before birth)
        """
        if field.data:
            today = date.today()
            
            # Check that the date is not in the future
            if field.data > today:
                raise ValidationError('Date of joining cannot be in the future')
                
            # Check that the date is after date of birth
            if self.date_of_birth.data and field.data < self.date_of_birth.data:
                raise ValidationError('Date of joining cannot be before date of birth')
    
    def validate_aadhar_number(self, field: IntegerField) -> None:
        """Validate Aadhar number format (12 digits).
        
        Args:
            field: The aadhar_number field to validate
            
        Raises:
            ValidationError: If the Aadhar number is not 12 digits
        """
        if field.data:
            aadhar_str = str(field.data)
            if len(aadhar_str) != 12:
                raise ValidationError('Aadhar number must be 12 digits')
                
            # Check if Aadhar already exists for another student
            existing_student = Student.query.filter_by(aadhar_number=field.data).first()
            if existing_student and (not self.pen_num.data or existing_student.pen_num != self.pen_num.data):
                raise ValidationError(f'Aadhar number already registered for student {existing_student.student_name}')
    
    def validate_pen_num(self, field: IntegerField) -> None:
        """Validate PEN number uniqueness for new students.
        
        Args:
            field: The pen_num field to validate
            
        Raises:
            ValidationError: If the PEN number already exists for a different student
        """
        if self.is_submitted():
            existing_student = Student.query.get(field.data)
            # If we're adding a new student and the PEN exists
            if existing_student:
                if not hasattr(self, 'student') or not self.student or self.student.pen_num != field.data:
                    raise ValidationError(f'PEN number {field.data} already exists for student {existing_student.student_name}')
    
    def validate_admission_number(self, field: IntegerField) -> None:
        """Validate admission number uniqueness.
        
        Args:
            field: The admission_number field to validate
            
        Raises:
            ValidationError: If the admission number already exists for a different student
        """
        if self.is_submitted():
            existing_student = Student.query.filter_by(admission_number=field.data).first()
            if existing_student and (not self.pen_num.data or existing_student.pen_num != self.pen_num.data):
                raise ValidationError(f'Admission number {field.data} already exists for student {existing_student.student_name}')
    
    def validate_contact_number(self, field: StringField) -> None:
        """Validate contact number format.
        
        Args:
            field: The contact_number field to validate
            
        Raises:
            ValidationError: If the contact number format is invalid
        """
        if field.data:
            # Remove any non-digit characters for validation
            digits_only = ''.join(filter(str.isdigit, field.data))
            if len(digits_only) < 10 or len(digits_only) > 15:
                raise ValidationError('Contact number must be between 10-15 digits')


class TransportForm(BaseForm):
    """Form for transport information."""
    
    transport_id = IntegerField(
        'Transport ID', 
        validators=[Optional()],
        description="Auto-generated ID (leave blank for new routes)"
    )
    
    pick_up_point = StringField(
        'Pick-up Point', 
        validators=[
            DataRequired(message="Pick-up Point is required"),
            Length(max=50, message="Pick-up Point must be less than 50 characters")
        ],
        description="Student pick-up location name"
    )
    
    route_number = IntegerField(
        'Route Number', 
        validators=[
            DataRequired(message="Route Number is required"),
            NumberRange(min=1, message="Route Number must be positive")
        ],
        description="Bus route number"
    )
    
    submit = SubmitField('Save')
    
    def validate_pick_up_point(self, field: StringField) -> None:
        """Validate pick-up point uniqueness.
        
        Args:
            field: The pick_up_point field to validate
            
        Raises:
            ValidationError: If the pick-up point already exists for a different route
        """
        if self.is_submitted():
            existing_transport = Transport.query.filter_by(pick_up_point=field.data).first()
            # If updating, ensure we're not checking against our own record
            if existing_transport and (not self.transport_id.data or existing_transport.transport_id != self.transport_id.data):
                raise ValidationError(f'Pick-up point "{field.data}" already exists (Route #{existing_transport.route_number})')


class ClassDetailsForm(BaseForm):
    """Form for class details."""
    
    pen_num = IntegerField(
        'PEN Number', 
        validators=[
            DataRequired(message="PEN Number is required"),
            NumberRange(min=1, message="PEN Number must be positive")
        ],
        description="Student's Permanent Enrollment Number"
    )
    
    year = IntegerField(
        'Academic Year', 
        validators=[
            DataRequired(message="Year is required"),
            NumberRange(min=2000, max=datetime.now().year + 1, message=f"Year must be between 2000 and {datetime.now().year + 1}")
        ],
        description="Academic year (e.g., 2023)"
    )
    
    current_class = IntegerField(
        'Current Class', 
        validators=[
            DataRequired(message="Current Class is required"),
            NumberRange(min=1, max=12, message="Class must be between 1 and 12")
        ],
        description="Student's current grade/class (1-12)"
    )
    
    section = StringField(
        'Section', 
        validators=[
            DataRequired(message="Section is required"),
            Length(max=2, message="Section must be less than 2 characters"),
            Regexp(r'^[A-Z]$', message="Section must be a single uppercase letter")
        ],
        description="Class section (A, B, C, etc.)"
    )
    
    roll_number = IntegerField(
        'Roll Number', 
        validators=[
            DataRequired(message="Roll Number is required"),
            NumberRange(min=1, message="Roll Number must be positive")
        ],
        description="Student's roll number in class"
    )
    
    photo_id = IntegerField(
        'Photo ID', 
        validators=[
            DataRequired(message="Photo ID is required"),
            NumberRange(min=1, message="Photo ID must be positive")
        ],
        description="ID number for student's photo"
    )
    
    language = SelectField(
        'Language', 
        choices=[
            ('Telugu', 'Telugu'), 
            ('Hindi', 'Hindi'), 
            ('Sanskrit', 'Sanskrit'),
            ('English', 'English')
        ], 
        validators=[DataRequired(message="Language selection is required")],
        description="Selected language subject"
    )
    
    vocational = SelectField(
        'Vocational', 
        choices=[
            ('Agriculture', 'Agriculture'), 
            ('Artificial Intelligence', 'Artificial Intelligence'), 
            ('Physical Activity Trainer', 'Physical Activity Trainer'), 
            ('Tourism', 'Tourism'),
            ('None', 'None')
        ], 
        validators=[DataRequired(message="Vocational selection is required")],
        description="Selected vocational subject"
    )
    
    currently_enrolled = BooleanField(
        'Currently Enrolled',
        default=True,
        description="Uncheck if student has left the school"
    )
    
    submit = SubmitField('Save')
    
    def validate_pen_num(self, field: IntegerField) -> None:
        """Validate PEN number exists in student table.
        
        Args:
            field: The pen_num field to validate
            
        Raises:
            ValidationError: If the PEN number doesn't exist
        """
        student = Student.query.get(field.data)
        if not student:
            raise ValidationError(f'Student with PEN number {field.data} does not exist')
        
    def validate_photo_id(self, field: IntegerField) -> None:
        """Validate photo ID uniqueness.
        
        Args:
            field: The photo_id field to validate
            
        Raises:
            ValidationError: If the photo ID already exists for a different student
        """
        if self.is_submitted():
            from school.models import ClassDetails
            existing = ClassDetails.query.filter_by(photo_id=field.data).first()
            # If the photo ID exists for a different student/year
            if existing and (existing.pen_num != self.pen_num.data or existing.year != self.year.data):
                raise ValidationError(f'Photo ID {field.data} is already in use')


class FeeForm(BaseForm):
    """Form for fee information."""
    
    pen_num = IntegerField(
        'PEN Number', 
        validators=[
            DataRequired(message="PEN Number is required"),
            NumberRange(min=1, message="PEN Number must be positive")
        ],
        description="Student's Permanent Enrollment Number"
    )
    
    year = IntegerField(
        'Academic Year', 
        validators=[
            DataRequired(message="Year is required"),
            NumberRange(min=2000, max=datetime.now().year + 1, message=f"Year must be between 2000 and {datetime.now().year + 1}")
        ],
        description="Academic year (e.g., 2023)"
    )
    
    school_fee = IntegerField(
        'School Fee', 
        validators=[
            DataRequired(message="School Fee is required"),
            NumberRange(min=0, message="School Fee cannot be negative")
        ],
        description="Annual school fee amount"
    )
    
    concession_reason = SelectField(
        'Concession Reason', 
        choices=[
            ('', 'None'),
            ('General', 'General (10%)'),
            ('Staff', 'Staff Child (50%)'), 
            ('Sibling', 'Sibling (10%)'), 
            ('OTP', 'One-Time Payment (10%)'), 
            ('TF', 'Topper Fee (5%)'), 
            ('FP', 'Financial Problem (20%)'), 
            ('EC', 'Excellence in Co-curricular (15%)'), 
            ('SC', 'Sports Champion (25%)')
        ], 
        validators=[Optional()],
        description="Reason for fee concession (percentage)"
    )
    
    transport_used = BooleanField(
        'Transport Used',
        description="Check if student uses school transport"
    )
    
    application_fee = IntegerField(
        'Application Fee', 
        validators=[
            DataRequired(message="Application Fee is required"),
            NumberRange(min=0, message="Application Fee cannot be negative")
        ],
        description="One-time application fee"
    )
    
    transport_fee = IntegerField(
        'Transport Fee', 
        validators=[Optional()],
        description="Annual transport fee (if transport is used)"
    )
    
    transport_fee_concession = IntegerField(
        'Transport Fee Concession', 
        validators=[Optional()],
        description="Discount on transport fee"
    )
    
    pick_up_point = SelectField(
        'Pick-up Point', 
        choices=[('', 'Select Pick-up Point')],
        validators=[Optional()],
        description="Location where student boards transport"
    )
    
    submit = SubmitField('Save')

    def __init__(self, *args, **kwargs):
        """Initialize the form with dynamic pick-up point choices.
        
        Args:
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments
        """
        super(FeeForm, self).__init__(*args, **kwargs)
        # Dynamically populate pick-up points from the database
        self.pick_up_point.choices = [('', 'Select Pick-up Point')] + [
            (t.pick_up_point, f"{t.pick_up_point} (Route #{t.route_number})") 
            for t in Transport.query.order_by(Transport.route_number).all()
        ]

    def validate_pen_num(self, field: IntegerField) -> None:
        """Validate PEN number exists in student table.
        
        Args:
            field: The pen_num field to validate
            
        Raises:
            ValidationError: If the PEN number doesn't exist
        """
        student = Student.query.get(field.data)
        if not student:
            raise ValidationError(f'Student with PEN number {field.data} does not exist')
    
    def validate_transport_used(self, field: BooleanField) -> None:
        """Validate transport details if transport is used.
        
        Args:
            field: The transport_used field to validate
            
        Raises:
            ValidationError: If required transport fields are missing
        """
        if field.data:
            pick_up_point = self.pick_up_point.data
            transport_fee = self.transport_fee.data
            
            if not pick_up_point:
                raise ValidationError('Pick-up point is required when transport is used')
                
            if not transport_fee or transport_fee <= 0:
                raise ValidationError('Transport fee is required and must be positive when transport is used')
                
            # Check if pick_up_point exists in Transport table
            transport = Transport.query.filter_by(pick_up_point=pick_up_point).first()
            if not transport and pick_up_point:
                raise ValidationError(f'Pick-up point "{pick_up_point}" does not exist in transport database')
        else:
            # If transport is not used, reset related fields
            self.transport_fee.data = 0
            self.transport_fee_concession.data = 0
            self.pick_up_point.data = ''
    
    def validate_transport_fee_concession(self, field: IntegerField) -> None:
        """Validate transport fee concession.
        
        Args:
            field: The transport_fee_concession field to validate
            
        Raises:
            ValidationError: If the concession exceeds the fee
        """
        if field.data and self.transport_fee.data and field.data > self.transport_fee.data:
            raise ValidationError('Transport fee concession cannot exceed the transport fee')


class FeeBreakdownForm(BaseForm):
    """Form for fee breakdown information."""
    
    pen_num = IntegerField(
        'PEN Number', 
        validators=[
            DataRequired(message="PEN Number is required"),
            NumberRange(min=1, message="PEN Number must be positive")
        ],
        description="Student's Permanent Enrollment Number"
    )
    
    year = IntegerField(
        'Academic Year', 
        validators=[
            DataRequired(message="Year is required"),
            NumberRange(min=2000, max=datetime.now().year + 1, message=f"Year must be between 2000 and {datetime.now().year + 1}")
        ],
        description="Academic year (e.g., 2023)"
    )
    
    fee_type = SelectField(
        'Fee Type', 
        choices=[
            ('School', 'School'), 
            ('Transport', 'Transport'), 
            ('Application', 'Application'),
            ('Other', 'Other')
        ], 
        validators=[DataRequired(message="Fee Type is required")],
        description="Type of fee being paid"
    )
    
    term = SelectField(
        'Term', 
        choices=[
            ('Q1', 'Quarter 1'), 
            ('Q2', 'Quarter 2'), 
            ('Q3', 'Quarter 3'),
            ('Q4', 'Quarter 4'),
            ('Full', 'Full Year')
        ], 
        validators=[DataRequired(message="Term is required")],
        description="Payment term/period"
    )
    
    payment_type = SelectField(
        'Payment Type', 
        choices=[
            ('Online', 'Online'), 
            ('Cash', 'Cash'),
            ('Cheque', 'Cheque'),
            ('Card', 'Card'),
            ('Bank Transfer', 'Bank Transfer')
        ], 
        validators=[DataRequired(message="Payment Type is required")],
        description="Method of payment"
    )
    
    paid = DecimalField(
        'Paid Amount', 
        validators=[
            DataRequired(message="Paid Amount is required"),
            NumberRange(min=0, message="Paid Amount cannot be negative")
        ],
        description="Amount paid by student"
    )
    
    due = DecimalField(
        'Due Amount', 
        validators=[
            NumberRange(min=0, message="Due Amount cannot be negative")
        ],
        default=0,
        description="Amount still to be paid"
    )
    
    receipt_no = IntegerField(
        'Receipt No', 
        validators=[
            DataRequired(message="Receipt Number is required"),
            NumberRange(min=1, message="Receipt Number must be positive")
        ],
        description="Payment receipt number"
    )
    
    fee_paid_date = DateField(
        'Fee Paid Date', 
        validators=[DataRequired(message="Fee Paid Date is required")],
        default=date.today,
        description="Date when fee was paid (YYYY-MM-DD)"
    )
    
    submit = SubmitField('Save')
    
    def validate_pen_num(self, field: IntegerField) -> None:
        """Validate PEN number exists and has fee record.
        
        Args:
            field: The pen_num field to validate
            
        Raises:
            ValidationError: If the PEN number doesn't exist or has no fee record
        """
        student = Student.query.get(field.data)
        if not student:
            raise ValidationError(f'Student with PEN number {field.data} does not exist')
            
        # Check if fee record exists for this student and year
        if self.year and self.year.data:
            fee = Fee.query.filter_by(pen_num=field.data, year=self.year.data).first()
            if not fee:
                raise ValidationError(f'No fee record exists for PEN {field.data} and year {self.year.data}')
    
    def validate_fee_paid_date(self, field: DateField) -> None:
        """Validate fee paid date is not in the future.
        
        Args:
            field: The fee_paid_date field to validate
            
        Raises:
            ValidationError: If the date is in the future
        """
        if field.data and field.data > date.today():
            raise ValidationError('Fee paid date cannot be in the future')
    
    def validate_fee_type(self, field: SelectField) -> None:
        """Validate fee type is valid for the student.
        
        Args:
            field: The fee_type field to validate
            
        Raises:
            ValidationError: If the fee type is invalid for this student
        """
        if field.data == 'Transport' and self.pen_num.data and self.year.data:
            # Check if the student uses transport
            fee = Fee.query.filter_by(pen_num=self.pen_num.data, year=self.year.data).first()
            if fee and not fee.transport_used:
                raise ValidationError('Student does not use transport services')


class TableSelectForm(BaseForm):
    """Form for selecting and filtering table data."""
    
    table_select = SelectField(
        'Select Table', 
        choices=[
            ('student', 'Student Information'), 
            ('classdetails', 'Class Details'), 
            ('fee', 'Fee Records'), 
            ('feebreakdown', 'Fee Payment History'), 
            ('transport', 'Transport Routes')
        ],
        description="Select the data table to view"
    )
    
    start_date = DateField(
        'Start Date', 
        format='%Y-%m-%d', 
        validators=[Optional()],
        description="Filter records from this date onwards (YYYY-MM-DD)"
    )
    
    end_date = DateField(
        'End Date', 
        format='%Y-%m-%d', 
        validators=[Optional()],
        description="Filter records until this date (YYYY-MM-DD)"
    )
    
    pen_num = StringField(
        'PEN Number', 
        validators=[
            Optional(),
            Regexp(r'^\d*$', message="PEN Number must contain only digits")
        ],
        description="Filter by student's PEN number"
    )
    
    class_filter = SelectField(
        'Class', 
        choices=[('', 'All Classes')] + [(str(i), str(i)) for i in range(1, 13)],
        validators=[Optional()],
        description="Filter by student's class"
    )
    
    submit = SubmitField('View Data')
    
    def validate_end_date(self, field: DateField) -> None:
        """Validate end date is after start date.
        
        Args:
            field: The end_date field to validate
            
        Raises:
            ValidationError: If end date is before start date
        """
        if field.data and self.start_date.data and field.data < self.start_date.data:
            raise ValidationError('End date must be after start date')
