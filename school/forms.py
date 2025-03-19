from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, IntegerField, DateField, DecimalField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, NumberRange, Optional
from school.models import User, Student, Transport
from flask_login import current_user
from datetime import date

class RegistrationForm(FlaskForm):
    username = StringField('Username', 
                           validators=[
                               DataRequired(), 
                               Length(min=2, max=20)
                           ])
    email = StringField('Email', 
                        validators=[
                            DataRequired(),
                            Email()
                        ])
    user_role = SelectField('User Role', 
                            choices=[('Admin', 'Admin'), 
                                     ('Teacher', 'Teacher'), 
                                     ('HR', 'Hr')],
                            validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', 
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one')
        
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email already exists. Please choose a different one')

class LoginForm(FlaskForm):
    email = StringField('Email', 
                        validators= 
                        [DataRequired(),
                         Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class UpdateAccountForm(FlaskForm):
    username = StringField('Username', 
                           validators= 
                           [DataRequired(), 
                            Length(min = 2, max = 20)])
    email = StringField('Email', 
                        validators= 
                        [DataRequired(),
                         Email()])
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField('Update')

    def validate_username(self,username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('That username is taken. Please choose a different one')
        
    def validate_email(self,email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('That email already exists. Please choose a different one')
            
class StudentForm(FlaskForm):
    pen_num = IntegerField('PEN Number', validators=[DataRequired()])
    admission_number = IntegerField('Admission Number', validators=[DataRequired()])
    aadhar_number = IntegerField('Aadhar Number', validators=[DataRequired()])
    student_name = StringField('Student Name', validators=[DataRequired(), Length(max=60)])
    father_name = StringField('Father Name', validators=[DataRequired(), Length(max=60)])
    mother_name = StringField('Mother Name', validators=[DataRequired(), Length(max=60)])
    gender = SelectField('Gender', choices=[('Male', 'Male'), ('Female', 'Female')], validators=[DataRequired()])
    date_of_birth = DateField('Date of Birth', validators=[DataRequired()])
    date_of_joining = DateField('Date of Joining', validators=[DataRequired()])
    contact_number = StringField('Contact Number', validators=[DataRequired(), Length(max=20)])
    village = StringField('Village', validators=[DataRequired(), Length(max=50)])
    submit = SubmitField('Save')

class TransportForm(FlaskForm):
    transport_id = IntegerField('Transport ID', validators=[Optional()])
    pick_up_point = StringField('Pick-up Point', validators=[DataRequired(), Length(max=50)])
    route_number = IntegerField('Route Number', validators=[DataRequired()])
    submit = SubmitField('Save')

class ClassDetailsForm(FlaskForm):
    pen_num = IntegerField('PEN Number', validators=[DataRequired()])
    year = IntegerField('Year', validators=[DataRequired()])
    current_class = IntegerField('Current Class', validators=[DataRequired(), NumberRange(min=1, max=12)])
    section = StringField('Section', validators=[DataRequired(), Length(max=2)])
    roll_number = IntegerField('Roll Number', validators=[DataRequired()])
    photo_id = IntegerField('Photo ID', validators=[DataRequired()])
    language = SelectField('Language', choices=[('Telugu', 'Telugu'), ('Hindi', 'Hindi'),('Sanskrit', 'Sanskrit')], validators=[DataRequired()])
    vocational = SelectField('Vocational', choices=[('Agriculture', 'Agriculture'), ('Artificial Intelligence', 'AI'), ('Physical Activity Trainer', 'PAT'), ('Tourism', 'Tourism')], validators=[DataRequired()])
    currently_enrolled = BooleanField('Currently Enrolled')
    submit = SubmitField('Save')

class FeeForm(FlaskForm):
    pen_num = IntegerField('PEN Number', validators=[DataRequired()])
    year = IntegerField('Year', validators=[DataRequired()])
    school_fee = IntegerField('School Fee', validators=[DataRequired()])
    concession_reason = SelectField('Concession Reason', choices=[('General', 'General'),('Staff', 'Staff'), ('Sibling', 'Sibling'), ('OTP', 'OTP'), ('TF', 'TF'), ('FP', 'FP'), ('EC', 'EC'), ('SC', 'SC')], validators=[DataRequired()])
    transport_used = BooleanField('Transport Used')
    application_fee = IntegerField('Application Fee', validators=[DataRequired()])
    transport_fee = IntegerField('Transport Fee', validators=[Optional()])
    transport_fee_concession = IntegerField('Transport Fee Concession', validators=[Optional()])
    pick_up_point = StringField('Pick-up Point', validators=[Optional(), Length(max=50)]) # Added pick_up_point
    submit = SubmitField('Save')

    # def validate_transport_used(form, field):
    #     if not field.data:  # If transport_used is False (not checked)
    #         form.transport_fee.data = 0
    #         form.transport_fee_concession.data = 0
    #         # form.transport_id.data = 0 # Removed as transport_id is determined by pick_up_point, not user input and setting it to 0 is incorrect.

class FeeBreakdownForm(FlaskForm):
    pen_num = IntegerField('PEN Number', validators=[DataRequired()])
    year = IntegerField('Year', validators=[DataRequired()])
    fee_type = SelectField('Fee Type', choices=[('School', 'School'), ('Transport', 'Transport'), ('Application', 'Application')], validators=[DataRequired()])
    term = SelectField('Term', choices=[('1', '1'), ('2', '2'), ('3', '3')], validators=[DataRequired()])
    payment_type = SelectField('Payment Type', choices=[('Online', 'Online'), ('Cash', 'Cash')], validators=[DataRequired()])
    paid = DecimalField('Paid Amount', validators=[DataRequired()])
    # due = DecimalField('Due Amount', validators=[DataRequired()])
    receipt_no = IntegerField('Receipt No', validators=[DataRequired()])
    fee_paid_date = DateField('Fee Paid Date', validators=[DataRequired()], default=date.today)
    submit = SubmitField('Save')

class TableSelectForm(FlaskForm):
    start_date = DateField('Start Date', validators=[Optional()], format='%Y-%m-%d')
    end_date = DateField('End Date', validators=[Optional()], format='%Y-%m-%d')
    submit = SubmitField('Filter')