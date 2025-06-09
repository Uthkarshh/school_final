"""
Routes module for the school fee management application.

This module defines all the routes and view functions for the application,
organizing them into logical sections for different features.
"""

import csv
import logging
import os
import secrets
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, date
from functools import wraps
from io import StringIO, TextIOWrapper
from typing import Any, Dict, List, Optional, Tuple, Union, cast

from flask import (Blueprint, Response, abort, current_app, flash, jsonify,
                  redirect, render_template, request,
                  send_from_directory, session, url_for)
from flask_login import current_user, login_required, login_user, logout_user
from PIL import Image
from sqlalchemy import distinct, func, case
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

from school import db, bcrypt, login_manager
from school.forms import (ClassDetailsForm, FeeBreakdownForm, FeeForm,
                        LoginForm, RegistrationForm, StudentForm,
                        TableSelectForm, TransportForm, UpdateAccountForm,
                        ChangePasswordForm)
from school.models import (ActivityLog, ClassDetails, Fee, FeeBreakdown,
                         Student, Transport, User, parse_date_from_string)
import re

# Configure logger for this module
logger = logging.getLogger(__name__)

# Constants
MAX_LOGIN_ATTEMPTS = int(os.environ.get('MAX_LOGIN_ATTEMPTS', '5'))
ACCOUNT_LOCKOUT_MINUTES = int(os.environ.get('ACCOUNT_LOCKOUT_MINUTES', '15'))
MAX_UPLOAD_SIZE = int(os.environ.get('MAX_UPLOAD_SIZE', str(5 * 1024 * 1024)))  # 5MB default
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
ITEMS_PER_PAGE = int(os.environ.get('ITEMS_PER_PAGE', '20'))

# Valid class choices - must match the ones in models.py and forms.py
VALID_CLASSES = ["Nursery", "LKG", "UKG", "I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X"]

# Create blueprints for different functional areas
auth_bp = Blueprint('auth_bp', __name__)
user_bp = Blueprint('user_bp', __name__)
admin_bp = Blueprint('admin_bp', __name__)
student_bp = Blueprint('student_bp', __name__)
fee_bp = Blueprint('fee_bp', __name__)
transport_bp = Blueprint('transport_bp', __name__)
report_bp = Blueprint('report_bp', __name__)


# --- Utility Functions ---
def log_exception(e: Exception, context: str = "") -> None:
    """Log an exception with context information.
    
    Args:
        e: The exception to log
        context: Additional context information
    """
    logger.error(f"{context}: {str(e)}", exc_info=True)


@contextmanager
def transaction_context():
    """Context manager for database transactions.
    
    Provides a safe context for database operations with automatic
    commit on success and rollback on exception.
    
    Yields:
        None
    
    Raises:
        Exception: Any exception that occurs during the transaction
    """
    try:
        yield
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        log_exception(e, "Database transaction error")
        raise


def admin_required(f):
    """Decorator to require admin role for route access.
    
    Args:
        f: The function to decorate
        
    Returns:
        Decorated function that checks admin authorization
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.user_role not in ['Admin', 'HR']:
            logger.warning(
                f"Unauthorized admin access attempt to {request.path} by "
                f"user ID: {getattr(current_user, 'id', 'Anonymous')}, "
                f"IP: {request.remote_addr}"
            )
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


def log_activity(action_type: str, entity_type: str, entity_id: str, description: str) -> None:
    """Log user activity to the activity_log table with IP address tracking.
    
    Args:
        action_type: Type of action performed (added, updated, deleted, etc.)
        entity_type: Type of entity affected (Student, Fee, etc.)
        entity_id: ID of the affected entity
        description: Human-readable description of the activity
    """
    try:
        if current_user.is_authenticated:
            activity = ActivityLog(
                user_id=current_user.id,
                action_type=action_type,
                entity_type=entity_type,
                entity_id=str(entity_id),
                description=description,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string if request.user_agent else None
            )
            db.session.add(activity)
            db.session.commit()
    except Exception as e:
        logger.error(f"Error logging activity: {str(e)}")


def get_record_by_primary_key(model: Any, **primary_keys) -> Optional[Any]:
    """Lookup a record by its primary key(s).
    
    Args:
        model: The SQLAlchemy model class
        **primary_keys: Primary key field names and values
        
    Returns:
        The record if found, None otherwise
    """
    try:
        return model.query.filter_by(**primary_keys).first()
    except SQLAlchemyError as e:
        logger.error(f"Database error retrieving {model.__name__}: {str(e)}")
        return None


def generate_error_csv(error_rows, operation_name):
    """Generate a downloadable CSV file containing errors.
    
    Args:
        error_rows: List of error messages or dictionaries with error details
        operation_name: Name of the operation for the filename
        
    Returns:
        Flask Response object with CSV data
    """
    output = StringIO()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    is_dict_format = isinstance(error_rows[0], dict) if error_rows else False
    
    if is_dict_format:
        fieldnames = error_rows[0].keys()
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for row in error_rows:
            writer.writerow(row)
    else:
        writer = csv.writer(output)
        writer.writerow(['Row', 'Error Message'])
        for i, error in enumerate(error_rows, 1):
            writer.writerow([i, error])
    
    filename = f'errors_{operation_name}_{timestamp}.csv'
    
    response = Response(output.getvalue(), mimetype='text/csv')
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    response.headers['X-Filename'] = filename
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response


def process_csv_import(request_files, file_key, process_row_func, redirect_url):
    """Generic CSV import processor with error handling and format detection.
    
    Args:
        request_files: The files from the request
        file_key: The key for the file in request_files
        process_row_func: Function to process each row of the CSV
        redirect_url: URL to redirect to after processing
        
    Returns:
        Redirect to appropriate page or downloadable CSV with errors
    """
    if file_key not in request_files:
        flash('No file part', 'danger')
        return redirect(request.url)

    file = request_files[file_key]
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(request.url)

    if not file.filename.endswith('.csv'):
        flash('Only CSV files are supported', 'danger')
        return redirect(request.url)

    try:
        # Validate content-type
        if not file.content_type or 'text/csv' not in file.content_type:
            file_content = file.read(1024)
            file.stream.seek(0)
            
            if not b',' in file_content and not b'\n' in file_content:
                flash('Invalid file format. Please upload a valid CSV file.', 'danger')
                return redirect(request.url)
        
        csv_file = TextIOWrapper(file.stream, encoding='utf-8-sig')
        csv_reader = csv.DictReader(csv_file)
        
        if csv_reader.fieldnames:
            logger.debug(f"CSV Headers: {csv_reader.fieldnames}")
        
        result = process_row_func(csv_reader)
        
        if isinstance(result, Response):
            return result
            
        return redirect(url_for(redirect_url))
    
    except Exception as e:
        logger.error(f"CSV processing error: {str(e)}", exc_info=True)
        db.session.rollback()
        error_rows = [f"Processing error: {str(e)}"]
        return generate_error_csv(error_rows, f"csv_import_{file_key}")


def apply_date_filter(query, model, start_date, end_date):
    """Apply date filters to a query.
    
    Args:
        query: The SQLAlchemy query object
        model: The model being queried
        start_date: Starting date for filter
        end_date: Ending date for filter
        
    Returns:
        Updated query with date filters applied
    """
    if hasattr(model, 'created_at'):
        if start_date:
            query = query.filter(model.created_at >= start_date)
        if end_date:
            end_date_inclusive = end_date + timedelta(days=1)
            query = query.filter(model.created_at < end_date_inclusive)
    return query


def prepare_csv_response(data, fieldnames, table_name):
    """Create a CSV response from data.
    
    Args:
        data: List of data records to include in CSV
        fieldnames: List of field names to include as columns
        table_name: Name of the table for the filename
        
    Returns:
        Flask Response object with CSV data
    """
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    
    for item in data:
        row = {field: getattr(item, field, '') for field in fieldnames}
        for field, value in row.items():
            if isinstance(value, (datetime, date)):
                row[field] = value.strftime('%Y-%m-%d')
        writer.writerow(row)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f'{table_name}_{timestamp}.csv'
    
    response = Response(output.getvalue(), mimetype='text/csv')
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    response.headers['X-Filename'] = filename
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response


def allowed_file(filename):
    """Check if a filename has an allowed extension.
    
    Args:
        filename: Filename to check
        
    Returns:
        True if file extension is allowed, False otherwise
    """
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def secure_save_file(file, directory, max_size=MAX_UPLOAD_SIZE):
    """Securely save an uploaded file with proper validation.
    
    Args:
        file: The file object to save
        directory: Directory to save the file in
        max_size: Maximum allowed file size in bytes
        
    Returns:
        Tuple of (success, filename_or_error_message)
    """
    if not file:
        return False, "No file provided"
        
    # Check file size
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)
    
    if file_size > max_size:
        return False, f"File too large. Maximum size is {max_size/1024/1024:.1f}MB"
    
    if not allowed_file(file.filename):
        return False, "File type not allowed. Allowed types: " + ", ".join(ALLOWED_EXTENSIONS)
    
    # Create secure filename
    random_hex = secrets.token_hex(8)
    _, file_ext = os.path.splitext(file.filename)
    filename = random_hex + file_ext.lower()
    
    # Ensure directory exists
    if not os.path.exists(directory):
        os.makedirs(directory)
    
    file_path = os.path.join(directory, filename)
    
    try:
        file.save(file_path)
        return True, filename
    except Exception as e:
        logger.error(f"Error saving file: {str(e)}")
        return False, f"Error saving file: {str(e)}"


def save_profile_picture(form_picture):
    """Save user profile picture with secure filename and image processing.
    
    Args:
        form_picture: The uploaded picture file
        
    Returns:
        Filename of saved image or None on failure
    """
    picture_path = os.path.join(current_app.root_path, 'static/profile_pics')
    
    success, result = secure_save_file(form_picture, picture_path)
    if not success:
        flash(result, 'danger')
        return None
        
    picture_filename = result
    saved_path = os.path.join(picture_path, picture_filename)
    
    try:
        output_size = (125, 125)
        img = Image.open(saved_path)
        img.thumbnail(output_size)
        img.save(saved_path)
        
        return picture_filename
    except Exception as e:
        logger.error(f"Error processing image: {str(e)}")
        try:
            os.remove(saved_path)
        except:
            pass
        flash(f"Error processing image: {str(e)}", 'danger')
        return None


def safe_commit():
    """Safely commit changes to database with error handling.
    
    Returns:
        True if commit was successful, False otherwise
    """
    try:
        db.session.commit()
        return True
    except SQLAlchemyError as e:
        db.session.rollback()
        log_exception(e, "Database error on commit")
        flash("An error occurred while saving data. Please try again.", "danger")
        return False


def paginate_results(query, page=None, per_page=None, error_out=False):
    """Standardized pagination function for all views.
    
    Args:
        query: SQLAlchemy query object to paginate
        page: Page number (starting from 1), defaults to request.args.get('page', 1)
        per_page: Number of items per page, defaults to ITEMS_PER_PAGE
        error_out: Whether to abort with 404 on out-of-range pages
        
    Returns:
        PaginationResult: Object containing items, pagination metadata, and rendering helpers
    """
    if page is None:
        try:
            page = int(request.args.get('page', 1))
        except (ValueError, TypeError):
            page = 1
    
    if per_page is None:
        per_page = ITEMS_PER_PAGE
    
    page = max(1, page)
    pagination = query.paginate(page=page, per_page=per_page, error_out=error_out)
    
    return pagination


def validate_edit_parameters(edit_pen_num, edit_year=None):
    """Validate edit parameters for consistency.
    
    Args:
        edit_pen_num: PEN number parameter
        edit_year: Optional year parameter
        
    Returns:
        Tuple of (validated_pen_num, validated_year) or (None, None) if invalid
    """
    try:
        pen_num = int(edit_pen_num) if edit_pen_num else None
        year = int(edit_year) if edit_year else None
        
        if pen_num and pen_num <= 0:
            return None, None
            
        if year and year <= 0:
            return None, None
            
        return pen_num, year
    except (ValueError, TypeError):
        return None, None


def format_datetime(value):
    """Format datetime values for templates.
    
    Args:
        value: Datetime value to format
        
    Returns:
        Formatted datetime string
    """
    if not value:
        return ""
        
    if isinstance(value, str):
        try:
            value = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            return value
    
    today = datetime.now().date()
    if value.date() == today:
        return f"Today at {value.strftime('%I:%M %p')}"
    
    yesterday = today - timedelta(days=1)
    if value.date() == yesterday:
        return f"Yesterday at {value.strftime('%I:%M %p')}"
    
    days_diff = (today - value.date()).days
    if days_diff < 7:
        return f"{days_diff} days ago"
    else:
        return value.strftime('%b %d, %Y')


def mask_aadhar(aadhar_number):
    """Mask Aadhar number for display in templates.
    
    Args:
        aadhar_number: Aadhar number to mask
        
    Returns:
        Masked Aadhar number string
    """
    if not aadhar_number:
        return ""
        
    aadhar_str = str(aadhar_number)
    masked = "X" * (len(aadhar_str) - 4) + aadhar_str[-4:]
    return masked


def _get_fallback_activities():
    """Get fallback activities when no activity log exists.
    
    Returns:
        List of activity dictionaries
    """
    activities = []
    
    # Get recent student records
    for student in Student.query.order_by(Student.created_at.desc()).limit(3):
        activities.append({
            'action_type': 'added',
            'entity_type': 'Student',
            'description': f"Added student: {student.student_name}",
            'user': {'username': student.created_by},
            'created_at': student.created_at
        })
    
    # Get recent fee payments
    for fee in FeeBreakdown.query.order_by(FeeBreakdown.created_at.desc()).limit(3):
        activities.append({
            'action_type': 'added',
            'entity_type': 'Fee',
            'description': f"Fee payment of ₹{float(fee.paid)} received for PEN {fee.pen_num}",
            'user': {'username': fee.created_by},
            'created_at': fee.created_at
        })
    
    return sorted(activities, key=lambda x: x['created_at'], reverse=True)[:5]


def _handle_failed_login(user):
    """Handle failed login attempts.
    
    Args:
        user: User object or None
    """
    if user:
        with transaction_context():
            user.failed_login_attempts += 1
            
            if user.failed_login_attempts >= MAX_LOGIN_ATTEMPTS:
                user.account_locked_until = datetime.now() + timedelta(minutes=ACCOUNT_LOCKOUT_MINUTES)
                flash(f'Too many failed login attempts. Your account has been locked for {ACCOUNT_LOCKOUT_MINUTES} minutes.', 'danger')
                log_activity('failed_login', 'User', user.id, f"Account locked due to {MAX_LOGIN_ATTEMPTS} failed login attempts: {user.username}")
            else:
                remaining_attempts = MAX_LOGIN_ATTEMPTS - user.failed_login_attempts
                flash(f'Login unsuccessful. Please check email and password. {remaining_attempts} attempts remaining.', 'danger')
                log_activity('failed_login', 'User', user.id, f"Failed login attempt ({user.failed_login_attempts}): {user.username}")
    else:
        flash('Login unsuccessful. Please check email and password', 'danger')
        time.sleep(0.5)


def _process_csv_batch(rows, batch_start, batch_size, process_row_func):
    """Process a batch of CSV rows.
    
    Args:
        rows: List of all CSV rows
        batch_start: Starting index for this batch
        batch_size: Size of the batch
        process_row_func: Function to process individual rows
        
    Returns:
        Tuple of (success_count, error_list)
    """
    batch_end = min(batch_start + batch_size, len(rows))
    current_batch = rows[batch_start:batch_end]
    
    batch_success = 0
    batch_errors = []
    
    try:
        with db.session.begin_nested():
            for row_index, row in enumerate(current_batch, start=batch_start+1):
                try:
                    process_row_func(row, row_index)
                    batch_success += 1
                except Exception as e:
                    error_message = f"Error in row {row_index}: {str(e)}"
                    logger.error(error_message)
                    batch_errors.append({
                        "Row": row_index,
                        "Error": str(e),
                        **{k: v for k, v in row.items() if k in ['pen_num', 'student_name', 'aadhar_number']}
                    })
    except Exception as e:
        logger.error(f"Error processing batch {batch_start//batch_size + 1}: {str(e)}")
        batch_errors.append({
            "Row": f"Batch {batch_start//batch_size + 1}",
            "Error": f"Failed to commit batch: {str(e)}",
            "pen_num": "",
            "student_name": "",
            "aadhar_number": ""
        })
    
    return batch_success, batch_errors


# --- Main Routes ---
def home():
    """Home page displaying dashboard information."""
    pages = [
        {"name": "Dashboard", "relative_path": url_for('home')},
        {"name": "Students", "relative_path": url_for('student_bp.student_form')},
        {"name": "Classes", "relative_path": url_for('student_bp.class_details_form')},
        {"name": "Fees", "relative_path": url_for('fee_bp.fee_form')},
        {"name": "Transport", "relative_path": url_for('transport_bp.transport_form')},
        {"name": "Reports", "relative_path": url_for('report_bp.view_table')},
        {"name": "Users", "relative_path": url_for('admin_bp.admin_users') if current_user.is_authenticated and current_user.user_role == 'Admin' else "#"},
        {"name": "Profile", "relative_path": url_for('user_bp.account')},
        {"name": "Settings", "relative_path": "#"}
    ]

    stats = {
        'student_count': 0,
        'fee_collection': 0,
        'transport_routes': 0,
        'pending_fees': 0,
        'fee_data': {'months': [], 'totals': []},
        'fee_type_distribution': {}
    }
    
    recent_activities = []

    if current_user.is_authenticated:
        try:
            stats['student_count'] = Student.query.count()
            stats['fee_collection'] = db.session.query(func.sum(FeeBreakdown.paid)).scalar() or 0
            stats['transport_routes'] = db.session.query(func.count(distinct(Transport.route_number))).scalar() or 0
            stats['pending_fees'] = FeeBreakdown.query.filter(FeeBreakdown.due > 0).count()
          
            recent_activities = ActivityLog.query.order_by(
                ActivityLog.created_at.desc()
            ).limit(5).all()
            
            if not recent_activities:
                recent_activities = _get_fallback_activities()
                
        except SQLAlchemyError as e:
            log_exception(e, "Database error on home page")
            flash("Error loading dashboard data. Please try again.", "warning")

    return render_template("home.html", pages=pages, stats=stats, recent_activities=recent_activities)


@login_required
def about():
    """About page."""
    return render_template("about.html", title="About me")


# --- Auth Routes ---
@auth_bp.route("/register", methods=['GET', 'POST'])
def register():
    """User registration route."""
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            password = form.password.data
            if len(password) < 8:
                flash('Password must be at least 8 characters long.', 'danger')
                return render_template('register.html', title='Register', form=form)
            
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            first_user = User.query.count() == 0
            
            with transaction_context():
                user = User(
                    username=form.username.data,
                    email=form.email.data,
                    user_role='Admin' if first_user else form.user_role.data,
                    password=hashed_password,
                    is_approved=first_user
                )
                db.session.add(user)
            
            if first_user:
                flash('Your admin account has been automatically approved. You can now log in.', 'info')
                flash('Admin role set automatically.', 'info')
                log_activity('added', 'User', user.id, f"First admin account created: {user.username}")
            else:
                flash('Your registration is pending admin approval. You will be notified once your account is approved.', 'info')
                flash('User role will be reviewed by admin.', 'info')
            
            return redirect(url_for('auth_bp.login'))
        except Exception as e:
            log_exception(e, "Error during user registration")
            flash('An error occurred during registration. Please try again.', 'danger')

    return render_template('register.html', title='Register', form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """User login route."""
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    form = LoginForm()
    if form.validate_on_submit():
        try:
            user = User.query.filter_by(email=form.email.data).first()
            
            if user and bcrypt.check_password_hash(user.password, form.password.data):
                if not user.is_approved:
                    flash('Your account is pending admin approval. Please wait for approval.', 'warning')
                    return render_template('login.html', title='Login', form=form)
                
                if user.is_locked:
                    remaining_time = user.account_locked_until - datetime.now()
                    flash(f'Your account is temporarily locked. Please try again in {remaining_time.seconds // 60} minutes.', 'danger')
                    return render_template('login.html', title='Login', form=form)
                
                with transaction_context():
                    user.failed_login_attempts = 0
                    user.last_login = datetime.now()
                
                login_user(user, remember=form.remember.data)
                log_activity('login', 'User', user.id, f"User logged in: {user.username}")
                
                session.pop('_csrf_token', None)
                
                next_page = request.args.get('next')
                if next_page:
                    if not next_page.startswith('/') or '//' in next_page:
                        next_page = url_for('home')
                return redirect(next_page or url_for('home'))
            else:
                _handle_failed_login(user)
                    
        except SQLAlchemyError as e:
            log_exception(e, "Database error during login")
            flash("An error occurred during login. Please try again.", "danger")
            
    return render_template('login.html', title='Login', form=form)


@auth_bp.route("/logout")
def logout():
    """User logout route."""
    if current_user.is_authenticated:
        log_activity('logout', 'User', current_user.id, f"User logged out: {current_user.username}")
    logout_user()
    
    session.clear()
    
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('home'))


# --- User Routes ---
@user_bp.route("/account", methods=["GET", "POST"])
@login_required
def account():
    """User account management route."""
    form = UpdateAccountForm()
    if form.validate_on_submit():
        try:
            with transaction_context():
                old_username = current_user.username
                current_user.username = form.username.data
                current_user.email = form.email.data
                
                if form.picture.data:
                    picture_file = save_profile_picture(form.picture.data)
                    if picture_file:
                        current_user.image_file = picture_file
            
            log_activity('updated', 'User', current_user.id, f"User profile updated: {old_username} → {current_user.username}")
            flash('Your account has been updated!', 'success')
            return redirect(url_for('user_bp.account'))
        except Exception as e:
            log_exception(e, "Error updating account")
            flash('An error occurred while updating your account. Please try again.', 'danger')
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
        
    return render_template('account.html', title='Account', form=form)


@user_bp.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """Change user password route."""
    form = ChangePasswordForm()
    
    if form.validate_on_submit():
        try:
            if not bcrypt.check_password_hash(current_user.password, form.current_password.data):
                flash('Current password is incorrect.', 'danger')
                return render_template('change_password.html', title='Change Password', form=form)
            
            if bcrypt.check_password_hash(current_user.password, form.new_password.data):
                flash('New password must be different from your current password.', 'warning')
                return render_template('change_password.html', title='Change Password', form=form)
            
            new_hashed_password = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
            
            with transaction_context():
                current_user.password = new_hashed_password
                current_user.failed_login_attempts = 0
                current_user.account_locked_until = None
            
            log_activity('updated', 'User', current_user.id, 
                        f"Password changed for user: {current_user.username}")
            
            flash('Your password has been changed successfully!', 'success')
            return redirect(url_for('user_bp.account'))
            
        except Exception as e:
            log_exception(e, "Error changing password")
            flash('An error occurred while changing your password. Please try again.', 'danger')
            return render_template('change_password.html', title='Change Password', form=form)
    
    return render_template('change_password.html', title='Change Password', form=form)


# --- Admin User Management ---
@admin_bp.route("/admin/users")
@login_required
@admin_required
def admin_users():
    """Admin user management route."""
    try:
        pagination = paginate_results(User.query.order_by(User.created_at.desc()))
        
        return render_template('admin_users.html', 
                              users=pagination.items, 
                              pagination=pagination,
                              title='Admin - User Management')
    except SQLAlchemyError as e:
        log_exception(e, "Database error retrieving users")
        flash("Error loading user data. Please try again.", "danger")
        return redirect(url_for('home'))


@admin_bp.route("/admin/users/toggle_approve/<int:user_id>")
@login_required
@admin_required
def toggle_user_approval(user_id):
    """Toggle user approval status."""
    try:
        with transaction_context():
            user = User.query.get_or_404(user_id)
            user.is_approved = not user.is_approved
            
        action = "approved" if user.is_approved else "access revoked"
        log_activity('updated', 'User', user.id, f"User {action}: {user.username}")
        
        flash_message = f'User {user.username} has been {action}.'
        flash_category = 'success' if user.is_approved else 'warning'
        flash(flash_message, flash_category)
    except Exception as e:
        log_exception(e, "Error toggling user approval")
        flash("An error occurred. Please try again.", "danger")
        
    return redirect(url_for('admin_bp.admin_users'))


@admin_bp.route("/admin/users/reject/<int:user_id>")
@login_required
@admin_required
def reject_user(user_id):
    """Reject and delete user account."""
    try:
        user = User.query.get_or_404(user_id)
        
        # Don't allow deleting the only admin account
        admin_count = User.query.filter_by(user_role='Admin', is_approved=True).count()
        if user.user_role == 'Admin' and admin_count <= 1:
            flash('Cannot delete the only admin account.', 'danger')
            return redirect(url_for('admin_bp.admin_users'))
            
        username = user.username
        
        with transaction_context():
            db.session.delete(user)
        
        log_activity('deleted', 'User', user_id, f"User rejected and deleted: {username}")
        flash(f'User {username} has been rejected and deleted.', 'danger')
    except Exception as e:
        log_exception(e, "Error rejecting user")
        flash("An error occurred. Please try again.", "danger")
        
    return redirect(url_for('admin_bp.admin_users'))


@admin_bp.route("/admin/users/bulk_approve")
@login_required
@admin_required
def bulk_approve_users():
    """Bulk approve multiple users."""
    user_ids = request.args.get('ids', '')
    if not user_ids:
        flash('No users selected', 'warning')
        return redirect(url_for('admin_bp.admin_users'))
    
    try:
        id_list = [int(id) for id in user_ids.split(',') if id.isdigit()]
        
        if not id_list:
            flash('Invalid user selection', 'warning')
            return redirect(url_for('admin_bp.admin_users'))
        
        with transaction_context():
            users = User.query.filter(User.id.in_(id_list)).all()
            approved_count = 0
            
            for user in users:
                if not user.is_approved:
                    user.is_approved = True
                    approved_count += 1
                    log_activity('updated', 'User', user.id, f"User approved in bulk operation: {user.username}")
        
        if approved_count > 0:
            flash(f'Successfully approved {approved_count} users', 'success')
        else:
            flash('No users needed approval', 'info')
    except Exception as e:
        log_exception(e, "Error in bulk user approval")
        flash("An error occurred during bulk approval. Please try again.", "danger")
    
    return redirect(url_for('admin_bp.admin_users'))


@admin_bp.route("/admin/users/bulk_reject")
@login_required
@admin_required
def bulk_reject_users():
    """Bulk reject and delete multiple users."""
    user_ids = request.args.get('ids', '')
    if not user_ids:
        flash('No users selected', 'warning')
        return redirect(url_for('admin_bp.admin_users'))
    
    try:
        id_list = [int(id) for id in user_ids.split(',') if id.isdigit()]
        
        if not id_list:
            flash('Invalid user selection', 'warning')
            return redirect(url_for('admin_bp.admin_users'))
        
        # Check if any selected users are the only admin
        admin_count = User.query.filter_by(user_role='Admin', is_approved=True).count()
        if admin_count <= 1:
            selected_admin = User.query.filter(
                User.id.in_(id_list),
                User.user_role == 'Admin',
                User.is_approved == True
            ).first()
            if selected_admin:
                flash('Cannot delete the only admin account.', 'danger')
                return redirect(url_for('admin_bp.admin_users'))
        
        deleted_count = 0
        deleted_users = []
        
        with transaction_context():
            users = User.query.filter(User.id.in_(id_list)).all()
            
            for user in users:
                deleted_users.append((user.id, user.username))
                db.session.delete(user)
                deleted_count += 1
        
        # Log activities outside the transaction
        for user_id, username in deleted_users:
            log_activity('deleted', 'User', user_id, f"User rejected in bulk operation: {username}")
        
        flash(f'Successfully deleted {deleted_count} users', 'success')
    except Exception as e:
        log_exception(e, "Error in bulk user rejection")
        flash("An error occurred during bulk rejection. Please try again.", "danger")
    
    return redirect(url_for('admin_bp.admin_users'))


# --- Student Management ---
@student_bp.route("/student_form", methods=['GET', 'POST'])
@login_required
@admin_required
def student_form():
    """Student form for adding and editing student records."""
    edit_pen_num = request.args.get('edit_pen_num')
    student = None
    
    if edit_pen_num:
        pen_num, _ = validate_edit_parameters(edit_pen_num)
        if pen_num:
            student = Student.query.get(pen_num)
            if not student:
                flash('Student not found with the specified PEN Number', 'danger')
        else:
            flash('Invalid PEN Number specified for editing', 'danger')
    
    form = StudentForm()
    form.student = student
    
    if student and request.method == 'GET':
        _populate_student_form(form, student)
    
    if form.validate_on_submit():
        try:
            with transaction_context():
                existing_student = Student.query.get(form.pen_num.data)
                
                if existing_student:
                    _update_student_record(existing_student, form)
                    log_activity('updated', 'Student', form.pen_num.data, 
                                f"Updated student record: {form.student_name.data}")
                    flash('Student record updated successfully!', 'success')
                else:
                    _create_student_record(form)
                    log_activity('added', 'Student', form.pen_num.data, 
                                f"Added new student: {form.student_name.data}")
                    flash('Student record added successfully!', 'success')
                
            return redirect(url_for('student_bp.student_form'))
        except IntegrityError as e:
            db.session.rollback()
            _handle_student_integrity_error(e)
            return render_template('student_form.html', title='Student Form', form=form, student=student)
        except Exception as e:
            db.session.rollback()
            log_exception(e, "Error saving student")
            flash('An error occurred while saving the student data. Please try again.', 'danger')
            return render_template('student_form.html', title='Student Form', form=form, student=student)
        
    return render_template('student_form.html', title='Student Form', form=form, student=student)


def _populate_student_form(form, student):
    """Populate student form with existing data."""
    form.pen_num.data = student.pen_num
    form.admission_number.data = student.admission_number
    form.aadhar_number.data = student.aadhar_number
    form.student_name.data = student.student_name
    form.father_name.data = student.father_name
    form.mother_name.data = student.mother_name
    form.gender.data = student.gender
    form.date_of_birth.data = student.date_of_birth
    form.date_of_joining.data = student.date_of_joining
    form.contact_number.data = student.contact_number
    form.village.data = student.village


def _update_student_record(student, form):
    """Update existing student record."""
    student.admission_number = form.admission_number.data
    student.aadhar_number = form.aadhar_number.data
    student.student_name = form.student_name.data
    student.father_name = form.father_name.data
    student.mother_name = form.mother_name.data
    student.gender = form.gender.data
    student.date_of_birth = form.date_of_birth.data
    student.date_of_joining = form.date_of_joining.data
    student.contact_number = form.contact_number.data
    student.village = form.village.data
    student.updated_by = current_user.username


def _create_student_record(form):
    """Create new student record."""
    student = Student(
        pen_num=form.pen_num.data,
        admission_number=form.admission_number.data,
        aadhar_number=form.aadhar_number.data,
        student_name=form.student_name.data,
        father_name=form.father_name.data,
        mother_name=form.mother_name.data,
        gender=form.gender.data,
        date_of_birth=form.date_of_birth.data,
        date_of_joining=form.date_of_joining.data,
        contact_number=form.contact_number.data,
        village=form.village.data,
        created_by=current_user.username
    )
    db.session.add(student)


def _handle_student_integrity_error(e):
    """Handle student record integrity errors."""
    if "student_aadhar_number_key" in str(e):
        flash('Error: A student with this Aadhar Number already exists.', 'danger')
    elif "student_admission_number_key" in str(e):
        flash('Error: A student with this Admission Number already exists.', 'danger')
    else:
        flash('Error: A unique constraint was violated. Please check your inputs.', 'danger')


@student_bp.route("/import_student_csv", methods=['GET', 'POST'])
@login_required
@admin_required
def import_student_csv():
    """Import student data from CSV file."""
    if request.method == 'POST':
        def process_student_rows(csv_reader):
            return _process_student_csv_import(csv_reader)
            
        return process_csv_import(request.files, 'student_csv', process_student_rows, 'home')
        
    return render_template('import_student_csv.html', title='Import Student CSV')


def _process_student_csv_import(csv_reader):
    """Process student CSV import."""
    total_records = 0
    records_committed = 0
    error_count = 0
    error_rows = []
    
    # Map column headers for dates
    date_column_map = {}
    if csv_reader.fieldnames:
        for field in csv_reader.fieldnames:
            if 'date_of_birth' in field.lower():
                date_column_map['date_of_birth'] = field
            elif 'date_of_joining' in field.lower():
                date_column_map['date_of_joining'] = field
    
    rows = list(csv_reader)
    total_rows = len(rows)
    logger.info(f"Processing {total_rows} rows from CSV")
    
    batch_size = 50
    
    for batch_start in range(0, total_rows, batch_size):
        batch_end = min(batch_start + batch_size, total_rows)
        current_batch = rows[batch_start:batch_end]
        
        logger.info(f"Processing batch {batch_start//batch_size + 1} (rows {batch_start+1}-{batch_end})")
        
        try:
            with db.session.begin_nested():
                batch_success = 0
                batch_errors = 0
                
                for row_index, row in enumerate(current_batch, start=batch_start+1):
                    try:
                        total_records += 1
                        
                        # Extract and validate data
                        student_data = _extract_student_data_from_row(row, date_column_map)
                        _validate_student_data(student_data)
                        
                        # Check for duplicates
                        _check_student_duplicates(student_data)

                        # Check if student exists by PEN
                        existing_student = db.session.get(Student, student_data['pen_num'])
                        
                        if existing_student:
                            _update_existing_student(existing_student, student_data)
                        else:
                            _create_new_student(student_data)
                            
                        batch_success += 1
                        
                    except Exception as e:
                        batch_errors += 1
                        error_count += 1
                        error_rows.append(_create_student_error_row(row_index, str(e), row))
        
            # If we made it here, the entire batch was committed
            records_committed += batch_success
            logger.info(f"Committed batch {batch_start//batch_size + 1}: {batch_success} successful, {batch_errors} failed")
        
        except Exception as e:
            db.session.rollback()
            error_count += batch_success
            logger.error(f"Failed to commit batch {batch_start//batch_size + 1}: {str(e)}")
            error_rows.append(_create_batch_error_row(batch_start//batch_size + 1, str(e)))
    
    # Final commit and reporting
    try:
        if records_committed > 0:
            db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed final commit: {str(e)}")
        error_rows.append(_create_final_error_row(str(e)))
    
    # Log the activity
    log_activity('imported', 'Student', 'BULK', 
                f"Imported {records_committed} students via CSV (from {total_records} records)")
    
    # Verify actual count
    actual_count = Student.query.count()
    logger.info(f"Actual student count in database: {actual_count}")
    
    if error_count > 0:
        error_rows.insert(0, _create_summary_error_row(records_committed, error_count))
        return generate_error_csv(error_rows, "student_import")
    else:
        flash(f"All {records_committed} records imported successfully!", 'success')
        flash(f"Current total student count in database: {actual_count}", 'info')
        
    return None


def _extract_student_data_from_row(row, date_column_map):
    """Extract and validate student data from CSV row."""
    try:
        pen_num = int(str(row.get("pen_num", "0")).strip() or 0)
        admission_number = int(str(row.get("admission_number", "0")).strip() or 0)
        
        aadhar_number = str(row.get("aadhar_number", "")).strip()
        aadhar_number = re.sub(r'[\s\-]', '', aadhar_number)
        
        if len(aadhar_number) != 12 or not aadhar_number.isdigit():
            raise ValueError("Aadhar number must be exactly 12 digits")
            
    except ValueError as ve:
        raise ValueError(f"Invalid number format: {str(ve)}")
        
    student_name = str(row.get("student_name", "")).strip()
    father_name = str(row.get("father_name", "")).strip()
    mother_name = str(row.get("mother_name", "")).strip()
    gender = str(row.get("gender", "")).strip()
    if gender not in ['Male', 'Female', 'Other']:
        gender = 'Male'
        
    contact_number = str(row.get("contact_number", "")).strip()
    village = str(row.get("village", "")).strip()
    
    # Parse dates
    date_of_birth_str = str(row.get(date_column_map.get('date_of_birth', 'date_of_birth'), "")).strip()
    date_of_joining_str = str(row.get(date_column_map.get('date_of_joining', 'date_of_joining'), "")).strip()
    
    try:
        date_of_birth = parse_date_from_string(date_of_birth_str, 'date_of_birth')
        date_of_joining = parse_date_from_string(date_of_joining_str, 'date_of_joining')
    except ValueError as ve:
        raise ValueError(f"Date parsing error: {str(ve)}")

    return {
        'pen_num': pen_num,
        'admission_number': admission_number,
        'aadhar_number': aadhar_number,
        'student_name': student_name,
        'father_name': father_name,
        'mother_name': mother_name,
        'gender': gender,
        'date_of_birth': date_of_birth,
        'date_of_joining': date_of_joining,
        'contact_number': contact_number,
        'village': village
    }


def _validate_student_data(student_data):
    """Validate student data."""
    if not student_data['pen_num'] or student_data['pen_num'] <= 0:
        raise ValueError("Invalid PEN Number (must be positive)")
    if not student_data['admission_number'] or student_data['admission_number'] <= 0:
        raise ValueError("Invalid Admission Number (must be positive)")
    if not student_data['student_name']:
        raise ValueError("Student name is required")


def _check_student_duplicates(student_data):
    """Check for duplicate student records."""
    existing_by_aadhar = Student.query.filter_by(aadhar_number=student_data['aadhar_number']).first()
    if existing_by_aadhar and existing_by_aadhar.pen_num != student_data['pen_num']:
        raise ValueError(
            f"Aadhar number {student_data['aadhar_number']} already exists for student "
            f"{existing_by_aadhar.student_name} (PEN: {existing_by_aadhar.pen_num})"
        )
    
    existing_by_admission = Student.query.filter_by(admission_number=student_data['admission_number']).first()
    if existing_by_admission and existing_by_admission.pen_num != student_data['pen_num']:
        raise ValueError(
            f"Admission number {student_data['admission_number']} already exists for student "
            f"{existing_by_admission.student_name} (PEN: {existing_by_admission.pen_num})"
        )


def _update_existing_student(existing_student, student_data):
    """Update existing student record."""
    existing_student.admission_number = student_data['admission_number']
    existing_student.aadhar_number = student_data['aadhar_number']
    existing_student.student_name = student_data['student_name']
    existing_student.father_name = student_data['father_name']
    existing_student.mother_name = student_data['mother_name']
    existing_student.gender = student_data['gender']
    existing_student.date_of_birth = student_data['date_of_birth']
    existing_student.date_of_joining = student_data['date_of_joining']
    existing_student.contact_number = student_data['contact_number']
    existing_student.village = student_data['village']
    existing_student.updated_by = current_user.username


def _create_new_student(student_data):
    """Create new student record."""
    new_student = Student(
        pen_num=student_data['pen_num'],
        admission_number=student_data['admission_number'],
        aadhar_number=student_data['aadhar_number'],
        student_name=student_data['student_name'],
        father_name=student_data['father_name'],
        mother_name=student_data['mother_name'],
        gender=student_data['gender'],
        date_of_birth=student_data['date_of_birth'],
        date_of_joining=student_data['date_of_joining'],
        contact_number=student_data['contact_number'],
        village=student_data['village'],
        created_by=current_user.username
    )
    db.session.add(new_student)


def _create_student_error_row(row_index, error, row):
    """Create error row for student import."""
    return {
        "Row": row_index, 
        "Error": error, 
        "PEN": row.get("pen_num", ""), 
        "Student Name": row.get("student_name", ""),
        "Aadhar": row.get("aadhar_number", ""),
        "Admission": row.get("admission_number", "")
    }


def _create_batch_error_row(batch_num, error):
    """Create batch error row."""
    return {
        "Row": f"Batch {batch_num}", 
        "Error": f"Failed to commit batch: {error}", 
        "PEN": "", 
        "Student Name": "",
        "Aadhar": "",
        "Admission": ""
    }


def _create_final_error_row(error):
    """Create final error row."""
    return {
        "Row": "FINAL", 
        "Error": f"Failed final commit: {error}", 
        "PEN": "", 
        "Student Name": "",
        "Aadhar": "",
        "Admission": ""
    }


def _create_summary_error_row(imported, failed):
    """Create summary error row."""
    return {
        "Row": "SUMMARY", 
        "Error": f"{imported} records imported successfully, {failed} failed",
        "PEN": "", 
        "Student Name": "",
        "Aadhar": "",
        "Admission": ""
    }


@student_bp.route("/class_details_form", methods=['GET', 'POST'])
@login_required
@admin_required
def class_details_form():
    """Class details form for adding and editing class information."""
    edit_pen_num = request.args.get('edit_pen_num')
    edit_year = request.args.get('edit_year')
    class_details = None
    
    if edit_pen_num and edit_year:
        pen_num, year = validate_edit_parameters(edit_pen_num, edit_year)
        if pen_num and year:
            class_details = ClassDetails.query.filter_by(
                pen_num=pen_num, 
                year=year
            ).first()
            
            if not class_details:
                flash('Class details record not found', 'danger')
        else:
            flash('Invalid parameters specified for editing', 'danger')
    
    form = ClassDetailsForm()
    
    if class_details and request.method == 'GET':
        _populate_class_details_form(form, class_details)
    
    if form.validate_on_submit():
        try:
            student = Student.query.get(form.pen_num.data)
            if not student:
                flash(f'Student with PEN {form.pen_num.data} does not exist', 'danger')
                return render_template('class_details_form.html', title='Class Details', form=form, class_details=class_details)
                
            with transaction_context():
                existing_record = ClassDetails.query.filter_by(
                    pen_num=form.pen_num.data, 
                    year=form.year.data
                ).first()
                
                if existing_record:
                    _update_class_details_record(existing_record, form)
                    log_activity('updated', 'ClassDetails', f"{form.pen_num.data}-{form.year.data}", 
                                f"Updated class details for student: {student.student_name}, Class: {form.current_class.data}-{form.section.data}")
                    flash('Class details updated successfully!', 'success')
                else:
                    _create_class_details_record(form)
                    log_activity('added', 'ClassDetails', f"{form.pen_num.data}-{form.year.data}", 
                                f"Added class details for student: {student.student_name}, Class: {form.current_class.data}-{form.section.data}")
                    flash('Class details added successfully!', 'success')
                
            return redirect(url_for('home'))
        except IntegrityError as e:
            db.session.rollback()
            _handle_class_details_integrity_error(e)
            return render_template('class_details_form.html', title='Class Details', form=form, class_details=class_details)
        except Exception as e:
            db.session.rollback()
            log_exception(e, "Error saving class details")
            flash('An error occurred while saving the class details. Please try again.', 'danger')
            return render_template('class_details_form.html', title='Class Details', form=form, class_details=class_details)
        
    return render_template('class_details_form.html', title='Class Details', form=form, class_details=class_details)


def _populate_class_details_form(form, class_details):
    """Populate class details form with existing data."""
    form.pen_num.data = class_details.pen_num
    form.year.data = class_details.year
    form.current_class.data = class_details.current_class
    form.section.data = class_details.section
    form.roll_number.data = class_details.roll_number
    form.photo_id.data = class_details.photo_id
    form.language.data = class_details.language
    form.vocational.data = class_details.vocational
    form.currently_enrolled.data = class_details.currently_enrolled


def _update_class_details_record(existing_record, form):
    """Update existing class details record."""
    existing_record.current_class = form.current_class.data
    existing_record.section = form.section.data
    existing_record.roll_number = form.roll_number.data
    existing_record.photo_id = form.photo_id.data
    existing_record.language = form.language.data
    existing_record.vocational = form.vocational.data
    existing_record.currently_enrolled = form.currently_enrolled.data
    existing_record.updated_by = current_user.username


def _create_class_details_record(form):
    """Create new class details record."""
    class_details = ClassDetails(
        pen_num=form.pen_num.data,
        year=form.year.data,
        current_class=form.current_class.data,
        section=form.section.data,
        roll_number=form.roll_number.data,
        photo_id=form.photo_id.data,
        language=form.language.data,
        vocational=form.vocational.data,
        currently_enrolled=form.currently_enrolled.data,
        created_by=current_user.username
    )
    db.session.add(class_details)


def _handle_class_details_integrity_error(e):
    """Handle class details integrity errors."""
    if "classdetails_photo_id_key" in str(e):
        flash('Error: A record with this photo ID already exists', 'danger')
    else:
        flash('Error: A unique constraint was violated. Please check your inputs.', 'danger')


@student_bp.route("/import_class_details_csv", methods=['GET', 'POST'])
@login_required
@admin_required
def import_class_details_csv():
    """Import class details from CSV file."""
    if request.method == 'POST':
        def process_class_details_rows(csv_reader):
            return _process_class_details_csv_import(csv_reader)
            
        return process_csv_import(request.files, 'class_details_csv', process_class_details_rows, 'home')
        
    return render_template('import_class_details_csv.html', title='Import Class Details CSV')


def _process_class_details_csv_import(csv_reader):
    """Process class details CSV import."""
    stats = {'imported': 0, 'updated': 0, 'failed': 0}
    error_rows = []
    
    batch_size = 100
    rows = list(csv_reader)
    
    for batch_start in range(0, len(rows), batch_size):
        batch_end = min(batch_start + batch_size, len(rows))
        current_batch = rows[batch_start:batch_end]
        
        try:
            with db.session.begin_nested():
                for row_index, row in enumerate(current_batch, start=batch_start+1):
                    try:
                        class_data = _extract_class_details_data_from_row(row)
                        _validate_class_details_data(class_data)
                        
                        # Check if student exists
                        student = Student.query.get(class_data['pen_num'])
                        if not student:
                            raise ValueError(f"Student with PEN {class_data['pen_num']} does not exist")

                        # Check for existing photo_id
                        _check_class_details_duplicates(class_data)

                        # Check if record exists
                        existing_record = ClassDetails.query.filter_by(
                            pen_num=class_data['pen_num'], 
                            year=class_data['year']
                        ).first()

                        if existing_record:
                            _update_existing_class_details(existing_record, class_data)
                            stats['updated'] += 1
                        else:
                            _create_new_class_details(class_data)
                            stats['imported'] += 1

                    except Exception as e:
                        stats['failed'] += 1
                        error_rows.append(_create_class_details_error_row(row_index, str(e), row))
                        
            logger.info(f"Committed batch {batch_start//batch_size + 1}")
                            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error processing batch {batch_start//batch_size + 1}: {str(e)}")
            error_rows.append(_create_class_details_batch_error_row(batch_start//batch_size + 1, str(e)))
    
    # Final commit
    try:
        if stats['imported'] > 0 or stats['updated'] > 0:
            db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed final commit: {str(e)}")
        error_rows.append(_create_class_details_final_error_row(str(e)))
    
    log_activity('imported', 'ClassDetails', 'BULK', 
                f"Imported {stats['imported']} class records, updated {stats['updated']} via CSV")
    
    if stats['failed'] > 0:
        error_rows.insert(0, _create_class_details_summary_error_row(stats))
        return generate_error_csv(error_rows, "class_details_import")
    else:
        flash(f"{stats['imported']} records imported, {stats['updated']} records updated successfully.", 'success')
        
    return None


def _extract_class_details_data_from_row(row):
    """Extract class details data from CSV row."""
    try:
        pen_num = int(str(row.get("pen_num", "0")).strip() or 0)
        year = int(str(row.get("year", "0")).strip() or 0)
        current_class = str(row.get("current_class", "")).strip()
        roll_number = int(str(row.get("roll_number", "0")).strip() or 0)
        photo_id = int(str(row.get("photo_id", "0")).strip() or 0)
    except ValueError as ve:
        raise ValueError(f"Invalid number format: {str(ve)}")
        
    section = str(row.get("section", "")).strip()
    language = str(row.get("language", "")).strip()
    vocational = str(row.get("vocational", "")).strip()
    
    currently_enrolled_str = str(row.get("currently_enrolled", "")).strip().lower()
    currently_enrolled = currently_enrolled_str in ["true", "1", "yes", "y", "t"]

    return {
        'pen_num': pen_num,
        'year': year,
        'current_class': current_class,
        'section': section,
        'roll_number': roll_number,
        'photo_id': photo_id,
        'language': language,
        'vocational': vocational,
        'currently_enrolled': currently_enrolled
    }


def _validate_class_details_data(class_data):
    """Validate class details data."""
    if not class_data['pen_num'] or class_data['pen_num'] <= 0:
        raise ValueError("Invalid PEN Number")
    if not class_data['year'] or class_data['year'] <= 0:
        raise ValueError("Invalid year")
    if not class_data['current_class'] or class_data['current_class'] not in VALID_CLASSES:
        raise ValueError(f"Invalid class. Must be one of: {', '.join(VALID_CLASSES)}")
    if not class_data['section']:
        raise ValueError("Section is required")
    if not class_data['photo_id'] or class_data['photo_id'] <= 0:
        raise ValueError("Invalid photo ID")


def _check_class_details_duplicates(class_data):
    """Check for duplicate class details records."""
    existing_by_photo_id = ClassDetails.query.filter_by(photo_id=class_data['photo_id']).first()
    if existing_by_photo_id and (existing_by_photo_id.pen_num != class_data['pen_num'] or existing_by_photo_id.year != class_data['year']):
        raise ValueError(
            f"Photo ID {class_data['photo_id']} already exists for student with PEN {existing_by_photo_id.pen_num} "
            f"in year {existing_by_photo_id.year}"
        )


def _update_existing_class_details(existing_record, class_data):
    """Update existing class details record."""
    existing_record.current_class = class_data['current_class']
    existing_record.section = class_data['section']
    existing_record.roll_number = class_data['roll_number']
    existing_record.photo_id = class_data['photo_id']
    existing_record.language = class_data['language']
    existing_record.vocational = class_data['vocational']
    existing_record.currently_enrolled = class_data['currently_enrolled']
    existing_record.updated_by = current_user.username


def _create_new_class_details(class_data):
    """Create new class details record."""
    db.session.add(ClassDetails(
        pen_num=class_data['pen_num'],
        year=class_data['year'],
        current_class=class_data['current_class'],
        section=class_data['section'],
        roll_number=class_data['roll_number'],
        photo_id=class_data['photo_id'],
        language=class_data['language'],
        vocational=class_data['vocational'],
        currently_enrolled=class_data['currently_enrolled'],
        created_by=current_user.username
    ))


def _create_class_details_error_row(row_index, error, row):
    """Create error row for class details import."""
    return {
        "Row": row_index,
        "Error": error,
        "PEN": row.get("pen_num", ""),
        "Year": row.get("year", ""),
        "Class": row.get("current_class", ""),
        "Photo ID": row.get("photo_id", "")
    }


def _create_class_details_batch_error_row(batch_num, error):
    """Create batch error row for class details."""
    return {
        "Row": f"Batch {batch_num}",
        "Error": f"Failed to commit batch: {error}",
        "PEN": "",
        "Year": "",
        "Class": "",
        "Photo ID": ""
    }


def _create_class_details_final_error_row(error):
    """Create final error row for class details."""
    return {
        "Row": "FINAL", 
        "Error": f"Failed final commit: {error}", 
        "PEN": "", 
        "Year": "",
        "Class": "",
        "Photo ID": ""
    }


def _create_class_details_summary_error_row(stats):
    """Create summary error row for class details."""
    return {
        "Row": "SUMMARY", 
        "Error": f"{stats['imported']} records imported, {stats['updated']} records updated, {stats['failed']} failed",
        "PEN": "", 
        "Year": "", 
        "Class": "",
        "Photo ID": ""
    }


# --- Transport Management ---
@transport_bp.route("/transport_form", methods=['GET', 'POST'])
@login_required
@admin_required
def transport_form():
    """Transport form for adding and editing transport routes."""
    edit_transport_id = request.args.get('edit_id')
    transport = None
    
    if edit_transport_id:
        transport_id, _ = validate_edit_parameters(edit_transport_id)
        if transport_id:
            transport = Transport.query.get(transport_id)
            if not transport:
                flash('Transport record not found', 'danger')
        else:
            flash('Invalid Transport ID', 'danger')
    
    form = TransportForm()
    
    if transport and request.method == 'GET':
        _populate_transport_form(form, transport)
    
    if form.validate_on_submit():
        try:
            with transaction_context():
                if form.transport_id.data:
                    transport = Transport.query.get(form.transport_id.data)
                    if transport:
                        _update_transport_record(transport, form)
                        log_activity('updated', 'Transport', transport.transport_id, 
                                    f"Updated transport route #{form.route_number.data} for {form.pick_up_point.data}")
                        flash('Transport record updated successfully!', 'success')
                    else:
                        flash('Transport record not found', 'danger')
                else:
                    _create_transport_record(form)
                    log_activity('added', 'Transport', 'NEW', 
                                f"Added transport route #{form.route_number.data} for {form.pick_up_point.data}")
                    flash('Transport record added successfully!', 'success')
                        
            return redirect(url_for('transport_bp.transport_form'))
        except IntegrityError as e:
            db.session.rollback()
            _handle_transport_integrity_error(e)
            return render_template('transport_form.html', title='Transport Form', form=form, transport=transport)
        except Exception as e:
            db.session.rollback()
            log_exception(e, "Error saving transport")
            flash('An error occurred while saving the transport data. Please try again.', 'danger')
            return render_template('transport_form.html', title='Transport Form', form=form, transport=transport)
        
    # Get all transports with pagination
    pagination = paginate_results(Transport.query.order_by(Transport.route_number, Transport.pick_up_point))
    transports = pagination.items
    
    return render_template('transport_form.html', 
                          title='Transport Form', 
                          form=form, 
                          transport=transport,
                          transports=transports,
                          pagination=pagination)


def _populate_transport_form(form, transport):
    """Populate transport form with existing data."""
    form.transport_id.data = transport.transport_id
    form.pick_up_point.data = transport.pick_up_point
    form.route_number.data = transport.route_number


def _update_transport_record(transport, form):
    """Update existing transport record."""
    transport.pick_up_point = form.pick_up_point.data
    transport.route_number = form.route_number.data
    transport.updated_by = current_user.username


def _create_transport_record(form):
    """Create new transport record."""
    transport = Transport(
        pick_up_point=form.pick_up_point.data,
        route_number=form.route_number.data,
        created_by=current_user.username
    )
    db.session.add(transport)


def _handle_transport_integrity_error(e):
    """Handle transport integrity errors."""
    if "transport_pick_up_point_key" in str(e):
        flash('Error: This pick-up point already exists', 'danger')
    else:
        flash('Error: A unique constraint was violated. Please check your inputs.', 'danger')


@transport_bp.route("/import_transport_csv", methods=['GET', 'POST'])
@login_required
@admin_required
def import_transport_csv():
    """Import transport data from CSV file."""
    if request.method == 'POST':
        def process_transport_rows(csv_reader):
            return _process_transport_csv_import(csv_reader)
            
        return process_csv_import(request.files, 'transport_csv', process_transport_rows, 'home')
        
    return render_template('import_transport_csv.html', title='Import Transport CSV')


def _process_transport_csv_import(csv_reader):
    """Process transport CSV import."""
    stats = {'imported': 0, 'failed': 0}
    error_rows = []
    
    existing_pick_up_points = {t.pick_up_point.lower(): t.transport_id for t in Transport.query.all()}
    
    batch_size = 100
    rows = list(csv_reader)
    
    for batch_start in range(0, len(rows), batch_size):
        batch_end = min(batch_start + batch_size, len(rows))
        current_batch = rows[batch_start:batch_end]
        
        try:
            with db.session.begin_nested():
                for row_index, row in enumerate(current_batch, start=batch_start+1):
                    try:
                        transport_data = _extract_transport_data_from_row(row)
                        _validate_transport_data(transport_data, existing_pick_up_points)

                        new_transport = Transport(
                            pick_up_point=transport_data['pick_up_point'],
                            route_number=transport_data['route_number'],
                            created_by=current_user.username
                        )
                        db.session.add(new_transport)
                        
                        existing_pick_up_points[transport_data['pick_up_point'].lower()] = True
                        stats['imported'] += 1

                    except Exception as e:
                        stats['failed'] += 1
                        error_rows.append(_create_transport_error_row(row_index, str(e), row))
                        
            logger.info(f"Committed batch {batch_start//batch_size + 1}")
        
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error processing batch {batch_start//batch_size + 1}: {str(e)}")
            error_rows.append(_create_transport_batch_error_row(batch_start//batch_size + 1, str(e)))
    
    # Final commit
    try:
        if stats['imported'] > 0:
            db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed final commit: {str(e)}")
        error_rows.append(_create_transport_final_error_row(str(e)))
    
    log_activity('imported', 'Transport', 'BULK', 
                f"Imported {stats['imported']} transport routes via CSV")
    
    if stats['failed'] > 0:
        error_rows.insert(0, _create_transport_summary_error_row(stats))
        return generate_error_csv(error_rows, "transport_import")
    else:
        flash(f"{stats['imported']} transport records imported successfully.", 'success')
        
    return None


def _extract_transport_data_from_row(row):
    """Extract transport data from CSV row."""
    pick_up_point = str(row.get("pick_up_point", "")).strip()
    
    try:
        route_number = int(str(row.get("route_number", "")).strip() or 0)
    except ValueError:
        raise ValueError("Invalid route number format")

    return {
        'pick_up_point': pick_up_point,
        'route_number': route_number
    }


def _validate_transport_data(transport_data, existing_pick_up_points):
    """Validate transport data."""
    if not transport_data['pick_up_point']:
        raise ValueError("Pick-up point is required")
    if transport_data['route_number'] <= 0:
        raise ValueError("Route number must be positive")
        
    if transport_data['pick_up_point'].lower() in existing_pick_up_points:
        raise ValueError(f"Pick-up point '{transport_data['pick_up_point']}' already exists")


def _create_transport_error_row(row_index, error, row):
    """Create error row for transport import."""
    return {
        "Row": row_index,
        "Error": error,
        "Pick-up Point": row.get("pick_up_point", ""),
        "Route #": row.get("route_number", "")
    }


def _create_transport_batch_error_row(batch_num, error):
    """Create batch error row for transport."""
    return {
        "Row": f"Batch {batch_num}",
        "Error": f"Failed to commit batch: {error}",
        "Pick-up Point": "",
        "Route #": ""
    }


def _create_transport_final_error_row(error):
    """Create final error row for transport."""
    return {
        "Row": "FINAL", 
        "Error": f"Failed final commit: {error}", 
        "Pick-up Point": "", 
        "Route #": ""
    }


def _create_transport_summary_error_row(stats):
    """Create summary error row for transport."""
    return {
        "Row": "SUMMARY", 
        "Error": f"{stats['imported']} transport records imported, {stats['failed']} failed",
        "Pick-up Point": "", 
        "Route #": ""
    }


# --- Fee Management ---
@fee_bp.route("/fee_form", methods=['GET', 'POST'])
@login_required
@admin_required
def fee_form():
    """Fee form for adding and editing fee information."""
    edit_pen_num = request.args.get('edit_pen_num')
    edit_year = request.args.get('edit_year')
    fee_record = None
    
    if edit_pen_num and edit_year:
        pen_num, year = validate_edit_parameters(edit_pen_num, edit_year)
        if pen_num and year:
            fee_record = Fee.query.filter_by(
                pen_num=pen_num, 
                year=year
            ).first()
            
            if not fee_record:
                flash('Fee record not found', 'danger')
        else:
            flash('Invalid parameters specified for editing', 'danger')
    
    form = FeeForm()
    
    if fee_record and request.method == 'GET':
        _populate_fee_form(form, fee_record)
    
    if form.validate_on_submit():
        try:
            student = Student.query.get(form.pen_num.data)
            if not student:
                flash(f'Student with PEN {form.pen_num.data} does not exist', 'danger')
                return render_template('fee_form.html', title='Fee Form', form=form, fee_record=fee_record)
                
            transport_data = _process_transport_data(form)
            if transport_data is None:
                return render_template('fee_form.html', title='Fee Form', form=form, fee_record=fee_record)
            
            student_name = student.student_name
            
            with transaction_context():
                existing_fee = Fee.query.filter_by(
                    pen_num=form.pen_num.data, 
                    year=form.year.data
                ).first()
                
                if existing_fee:
                    _update_fee_record(existing_fee, form, transport_data)
                    log_activity('updated', 'Fee', f"{form.pen_num.data}-{form.year.data}", 
                                f"Updated fee record for student: {student_name}, Year: {form.year.data}")
                    flash('Fee record updated successfully!', 'success')
                else:
                    _create_fee_record(form, transport_data)
                    log_activity('added', 'Fee', f"{form.pen_num.data}-{form.year.data}", 
                                f"Added fee record for student: {student_name}, Year: {form.year.data}")
                    flash('Fee record added successfully!', 'success')
                
            return redirect(url_for('home'))
        except IntegrityError as e:
            db.session.rollback()
            flash('Error: A unique constraint was violated. Please check your inputs.', 'danger')
            return render_template('fee_form.html', title='Fee Form', form=form, fee_record=fee_record)
        except Exception as e:
            db.session.rollback()
            log_exception(e, "Error saving fee record")
            flash('An error occurred while saving the fee data. Please try again.', 'danger')
            return render_template('fee_form.html', title='Fee Form', form=form, fee_record=fee_record)
        
    return render_template('fee_form.html', title='Fee Form', form=form, fee_record=fee_record)


def _populate_fee_form(form, fee_record):
    """Populate fee form with existing data."""
    form.pen_num.data = fee_record.pen_num
    form.year.data = fee_record.year
    form.school_fee.data = fee_record.school_fee
    form.concession_reason.data = fee_record.concession_reason
    form.transport_used.data = fee_record.transport_used
    form.application_fee.data = fee_record.application_fee
    
    if fee_record.transport_used and fee_record.transport:
        form.pick_up_point.data = fee_record.transport.pick_up_point
        form.transport_fee.data = fee_record.transport_fee
        form.transport_fee_concession.data = fee_record.transport_fee_concession


def _process_transport_data(form):
    """Process transport data from form."""
    transport_used = form.transport_used.data
    transport_id = None
    transport_fee = 0
    transport_fee_concession = 0
    
    if transport_used:
        pick_up_point = form.pick_up_point.data
        if not pick_up_point:
            flash('Pick-up point is required when transport is used', 'danger')
            return None
            
        transport = Transport.query.filter_by(pick_up_point=pick_up_point).first()
        if not transport:
            flash(f'Pick-up point "{pick_up_point}" does not exist in transport database', 'danger')
            return None
            
        transport_id = transport.transport_id
        transport_fee = form.transport_fee.data or 0
        transport_fee_concession = form.transport_fee_concession.data or 0

    return {
        'transport_used': transport_used,
        'transport_id': transport_id,
        'transport_fee': transport_fee,
        'transport_fee_concession': transport_fee_concession
    }


def _update_fee_record(existing_fee, form, transport_data):
    """Update existing fee record."""
    existing_fee.school_fee = form.school_fee.data
    existing_fee.concession_reason = form.concession_reason.data
    existing_fee.transport_used = transport_data['transport_used']
    existing_fee.application_fee = form.application_fee.data
    existing_fee.transport_fee = transport_data['transport_fee']
    existing_fee.transport_fee_concession = transport_data['transport_fee_concession']
    existing_fee.transport_id = transport_data['transport_id']
    existing_fee.updated_by = current_user.username


def _create_fee_record(form, transport_data):
    """Create new fee record."""
    fee = Fee(
        pen_num=form.pen_num.data,
        year=form.year.data,
        school_fee=form.school_fee.data,
        concession_reason=form.concession_reason.data,
        transport_used=transport_data['transport_used'],
        application_fee=form.application_fee.data,
        transport_fee=transport_data['transport_fee'],
        transport_fee_concession=transport_data['transport_fee_concession'],
        transport_id=transport_data['transport_id'],
        created_by=current_user.username
    )
    db.session.add(fee)


@fee_bp.route("/import_fee_csv", methods=['GET', 'POST'])
@login_required
@admin_required
def import_fee_csv():
    """Import fee data from CSV file."""
    if request.method == 'POST':
        def process_fee_rows(csv_reader):
            return _process_fee_csv_import(csv_reader)
            
        return process_csv_import(request.files, 'fee_csv', process_fee_rows, 'home')
        
    return render_template('import_fee_csv.html', title='Import Fee CSV')


def _process_fee_csv_import(csv_reader):
    """Process fee CSV import."""
    stats = {'imported': 0, 'updated': 0, 'failed': 0}
    error_rows = []
    
    # Prefetch transport data
    transports = {t.pick_up_point: t.transport_id for t in Transport.query.all()}
    
    batch_size = 100
    rows = list(csv_reader)
    
    for batch_start in range(0, len(rows), batch_size):
        batch_end = min(batch_start + batch_size, len(rows))
        current_batch = rows[batch_start:batch_end]
        
        try:
            with db.session.begin_nested():
                for row_index, row in enumerate(current_batch, start=batch_start+1):
                    try:
                        fee_data = _extract_fee_data_from_row(row)
                        _validate_fee_data(fee_data)
                        
                        # Check if student exists
                        student = Student.query.get(fee_data['pen_num'])
                        if not student:
                            raise ValueError(f"Student with PEN {fee_data['pen_num']} does not exist")

                        # Process transport
                        transport_id = _process_fee_transport_data(fee_data, transports, row)

                        # Check if record exists
                        existing_fee = Fee.query.filter_by(
                            pen_num=fee_data['pen_num'], 
                            year=fee_data['year']
                        ).first()

                        if existing_fee:
                            _update_existing_fee(existing_fee, fee_data, transport_id)
                            stats['updated'] += 1
                        else:
                            _create_new_fee(fee_data, transport_id)
                            stats['imported'] += 1

                    except Exception as e:
                        stats['failed'] += 1
                        error_rows.append(_create_fee_error_row(row_index, str(e), row, student if 'student' in locals() else None))
                        
            logger.info(f"Committed batch {batch_start//batch_size + 1}")
                    
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error processing batch {batch_start//batch_size + 1}: {str(e)}")
            error_rows.append(_create_fee_batch_error_row(batch_start//batch_size + 1, str(e)))
    
    # Final commit
    try:
        if stats['imported'] > 0 or stats['updated'] > 0:
            db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed final commit: {str(e)}")
        error_rows.append(_create_fee_final_error_row(str(e)))
    
    log_activity('imported', 'Fee', 'BULK', 
                f"Imported {stats['imported']} fee records, updated {stats['updated']} via CSV")
    
    if stats['failed'] > 0:
        error_rows.insert(0, _create_fee_summary_error_row(stats))
        return generate_error_csv(error_rows, "fee_import")
    else:
        flash(f"{stats['imported']} records imported, {stats['updated']} records updated successfully.", 'success')
        
    return None


def _extract_fee_data_from_row(row):
    """Extract fee data from CSV row."""
    try:
        pen_num = int(str(row.get("pen_num", "0")).strip() or 0)
        year = int(str(row.get("year", "0")).strip() or 0)
        school_fee = float(str(row.get("school_fee", "0.0")).strip() or 0.0)
        application_fee = float(str(row.get("application_fee", "0.0")).strip() or 0.0)
        transport_fee = float(str(row.get("transport_fee", "0.0")).strip() or 0.0)
        transport_fee_concession = float(str(row.get("transport_fee_concession", "0.0")).strip() or 0.0)
    except ValueError as ve:
        raise ValueError(f"Invalid number format: {str(ve)}")
        
    concession_reason = str(row.get("concession_reason", "")).strip()
    
    transport_used_str = str(row.get("transport_used", "")).strip().lower()
    transport_used = transport_used_str in ["true", "1", "yes", "y", "t"]
    
    pick_up_point = str(row.get("pick_up_point", "")).strip()

    return {
        'pen_num': pen_num,
        'year': year,
        'school_fee': school_fee,
        'concession_reason': concession_reason,
        'transport_used': transport_used,
        'application_fee': application_fee,
        'transport_fee': transport_fee,
        'transport_fee_concession': transport_fee_concession,
        'pick_up_point': pick_up_point
    }


def _validate_fee_data(fee_data):
    """Validate fee data."""
    if not fee_data['pen_num'] or fee_data['pen_num'] <= 0:
        raise ValueError("Invalid PEN Number")
    if not fee_data['year'] or fee_data['year'] <= 0:
        raise ValueError("Invalid year")
    if fee_data['school_fee'] < 0:
        raise ValueError("School fee cannot be negative")
    if fee_data['application_fee'] < 0:
        raise ValueError("Application fee cannot be negative")
    if fee_data['transport_used'] and not fee_data['pick_up_point']:
        raise ValueError("Pick-up point is required when transport is used")


def _process_fee_transport_data(fee_data, transports, row):
    """Process transport data for fee import."""
    transport_id = None
    transport_fee = fee_data['transport_fee']
    transport_fee_concession = fee_data['transport_fee_concession']
    
    if fee_data['transport_used'] and fee_data['pick_up_point']:
        transport_id = transports.get(fee_data['pick_up_point'])
        if not transport_id:
            try:
                route_number = int(str(row.get("route_number", "0")).strip() or 0)
                if route_number <= 0:
                    raise ValueError("Route number must be positive")
                    
                new_transport = Transport(
                    pick_up_point=fee_data['pick_up_point'],
                    route_number=route_number,
                    created_by=current_user.username
                )
                db.session.add(new_transport)
                db.session.flush()
                transport_id = new_transport.transport_id
                transports[fee_data['pick_up_point']] = transport_id
                logger.info(f"Created new transport pick-up point: {fee_data['pick_up_point']}")
            except Exception as e:
                raise ValueError(f"Could not create transport record: {str(e)}")
    
    if not fee_data['transport_used']:
        transport_id = None
        transport_fee = 0
        transport_fee_concession = 0
    
    return transport_id


def _update_existing_fee(existing_fee, fee_data, transport_id):
    """Update existing fee record."""
    existing_fee.school_fee = int(fee_data['school_fee'])
    existing_fee.concession_reason = fee_data['concession_reason']
    existing_fee.transport_used = fee_data['transport_used']
    existing_fee.application_fee = int(fee_data['application_fee'])
    existing_fee.transport_fee = int(fee_data['transport_fee'])
    existing_fee.transport_fee_concession = int(fee_data['transport_fee_concession'])
    existing_fee.transport_id = transport_id
    existing_fee.updated_by = current_user.username


def _create_new_fee(fee_data, transport_id):
    """Create new fee record."""
    db.session.add(Fee(
        pen_num=fee_data['pen_num'],
        year=fee_data['year'],
        school_fee=int(fee_data['school_fee']),
        concession_reason=fee_data['concession_reason'],
        transport_used=fee_data['transport_used'],
        application_fee=int(fee_data['application_fee']),
        transport_fee=int(fee_data['transport_fee']),
        transport_fee_concession=int(fee_data['transport_fee_concession']),
        transport_id=transport_id,
        created_by=current_user.username
    ))


def _create_fee_error_row(row_index, error, row, student):
    """Create error row for fee import."""
    return {
        "Row": row_index,
        "Error": error,
        "PEN": row.get("pen_num", ""),
        "Year": row.get("year", ""),
        "Student": student.student_name if student else ""
    }


def _create_fee_batch_error_row(batch_num, error):
    """Create batch error row for fee."""
    return {
        "Row": f"Batch {batch_num}",
        "Error": f"Failed to commit batch: {error}",
        "PEN": "",
        "Year": "",
        "Student": ""
    }


def _create_fee_final_error_row(error):
    """Create final error row for fee."""
    return {
        "Row": "FINAL", 
        "Error": f"Failed final commit: {error}", 
        "PEN": "", 
        "Year": "",
        "Student": ""
    }


def _create_fee_summary_error_row(stats):
    """Create summary error row for fee."""
    return {
        "Row": "SUMMARY", 
        "Error": f"{stats['imported']} records imported, {stats['updated']} records updated, {stats['failed']} failed",
        "PEN": "", 
        "Year": "", 
        "Student": ""
    }


@fee_bp.route("/fee_breakdown_form", methods=['GET', 'POST'])
@login_required
@admin_required
def fee_breakdown_form():
    """Fee breakdown form for adding and editing fee payment details."""
    edit_pen_num = request.args.get('edit_pen_num')
    edit_year = request.args.get('edit_year')
    edit_fee_type = request.args.get('edit_fee_type')
    edit_term = request.args.get('edit_term')
    edit_payment_type = request.args.get('edit_payment_type')
    fee_breakdown = None
    
    if all([edit_pen_num, edit_year, edit_fee_type, edit_term, edit_payment_type]):
        pen_num, year = validate_edit_parameters(edit_pen_num, edit_year)
        if pen_num and year:
            fee_breakdown = FeeBreakdown.query.filter_by(
                pen_num=pen_num,
                year=year,
                fee_type=edit_fee_type,
                term=edit_term,
                payment_type=edit_payment_type
            ).first()
            
            if not fee_breakdown:
                flash('Fee breakdown record not found', 'danger')
        else:
            flash('Invalid parameters specified for editing', 'danger')
    
    form = FeeBreakdownForm()
    
    if fee_breakdown and request.method == 'GET':
        _populate_fee_breakdown_form(form, fee_breakdown)
    
    if form.validate_on_submit():
        try:
            fee_record = Fee.query.filter_by(pen_num=form.pen_num.data, year=form.year.data).first()
            if not fee_record:
                flash(f'Fee record not found for PEN Number: {form.pen_num.data} and Year: {form.year.data}. Please add fee details first.', 'danger')
                return render_template('fee_breakdown_form.html', title='Fee Breakdown', form=form, fee_breakdown=fee_breakdown)

            student = Student.query.get(form.pen_num.data)
            if not student:
                flash(f'Student with PEN {form.pen_num.data} does not exist', 'danger')
                return render_template('fee_breakdown_form.html', title='Fee Breakdown', form=form, fee_breakdown=fee_breakdown)
                
            student_name = student.student_name

            # Calculate term fee amount
            calculated_due = _calculate_fee_breakdown_due(fee_record, form)
            if calculated_due is None:
                return render_template('fee_breakdown_form.html', title='Fee Breakdown', form=form, fee_breakdown=fee_breakdown)

            with transaction_context():
                existing_fee_breakdown = FeeBreakdown.query.filter_by(
                    pen_num=form.pen_num.data,
                    year=form.year.data,
                    fee_type=form.fee_type.data,
                    term=form.term.data,
                    payment_type=form.payment_type.data
                ).first()
                
                if existing_fee_breakdown:
                    _update_fee_breakdown_record(existing_fee_breakdown, form, calculated_due)
                    log_activity('updated', 'FeeBreakdown', 
                                f"{form.pen_num.data}-{form.year.data}-{form.fee_type.data}-{form.term.data}-{form.payment_type.data}", 
                                f"Updated fee payment of ₹{form.paid.data} for {student_name}, " +
                                f"Fee type: {form.fee_type.data}, Term: {form.term.data}")
                    flash('Fee breakdown updated successfully!', 'success')
                else:
                    _create_fee_breakdown_record(form, calculated_due)
                    log_activity('added', 'FeeBreakdown', 
                                f"{form.pen_num.data}-{form.year.data}-{form.fee_type.data}-{form.term.data}-{form.payment_type.data}", 
                                f"Received fee payment of ₹{form.paid.data} from {student_name}, " +
                                f"Fee type: {form.fee_type.data}, Term: {form.term.data}")
                    flash('Fee breakdown added successfully!', 'success')
                
            return redirect(url_for('home'))
        except IntegrityError as e:
            db.session.rollback()
            _handle_fee_breakdown_integrity_error(e)
            return render_template('fee_breakdown_form.html', title='Fee Breakdown', form=form, fee_breakdown=fee_breakdown)
        except Exception as e:
            db.session.rollback()
            log_exception(e, "Error saving fee breakdown")
            flash('An error occurred while saving the fee breakdown data. Please try again.', 'danger')
            return render_template('fee_breakdown_form.html', title='Fee Breakdown', form=form, fee_breakdown=fee_breakdown)
        
    return render_template('fee_breakdown_form.html', title='Fee Breakdown', form=form, fee_breakdown=fee_breakdown)


def _populate_fee_breakdown_form(form, fee_breakdown):
    """Populate fee breakdown form with existing data."""
    form.pen_num.data = fee_breakdown.pen_num
    form.year.data = fee_breakdown.year
    form.fee_type.data = fee_breakdown.fee_type
    form.term.data = fee_breakdown.term
    form.payment_type.data = fee_breakdown.payment_type
    form.paid.data = fee_breakdown.paid
    form.receipt_no.data = fee_breakdown.receipt_no
    form.fee_paid_date.data = fee_breakdown.fee_paid_date


def _calculate_fee_breakdown_due(fee_record, form):
    """Calculate due amount for fee breakdown."""
    terms_for_type = 1 if form.fee_type.data == 'Application' else 3
    
    if form.fee_type.data == 'Application':
        total_fee_for_type = fee_record.application_fee
    elif form.fee_type.data == 'Transport':
        if fee_record.transport_used:
            total_fee_for_type = fee_record.transport_fee - fee_record.transport_fee_concession
        else:
            flash(f'Student with PEN Number: {form.pen_num.data} has not opted in for Transport for Year: {form.year.data}', 'danger')
            return None
    elif form.fee_type.data == 'School':
        total_fee_for_type = fee_record.school_fee - fee_record.school_fee_concession
        
    term_fee = total_fee_for_type / terms_for_type if terms_for_type > 0 else 0
    calculated_due = max(0, term_fee - float(form.paid.data))
    
    return calculated_due


def _update_fee_breakdown_record(existing_fee_breakdown, form, calculated_due):
    """Update existing fee breakdown record."""
    existing_fee_breakdown.paid = form.paid.data
    existing_fee_breakdown.due = calculated_due
    existing_fee_breakdown.receipt_no = form.receipt_no.data
    existing_fee_breakdown.fee_paid_date = form.fee_paid_date.data
    existing_fee_breakdown.updated_by = current_user.username


def _create_fee_breakdown_record(form, calculated_due):
    """Create new fee breakdown record."""
    db.session.add(FeeBreakdown(
        pen_num=form.pen_num.data,
        year=form.year.data,
        fee_type=form.fee_type.data,
        term=form.term.data,
        payment_type=form.payment_type.data,
        paid=form.paid.data,
        due=calculated_due,
        receipt_no=form.receipt_no.data,
        fee_paid_date=form.fee_paid_date.data,
        created_by=current_user.username
    ))


def _handle_fee_breakdown_integrity_error(e):
    """Handle fee breakdown integrity errors."""
    if "feebreakdown_receipt_no_key" in str(e):
        flash('Error: This receipt number already exists', 'danger')
    else:
        flash('Error: A unique constraint was violated. Please check your inputs.', 'danger')


@fee_bp.route("/import_fee_breakdown_csv", methods=['GET', 'POST'])
@login_required
@admin_required
def import_fee_breakdown_csv():
    """Import fee breakdown data from CSV file."""
    if request.method == 'POST':
        def process_fee_breakdown_rows(csv_reader):
            return _process_fee_breakdown_csv_import(csv_reader)
            
        return process_csv_import(request.files, 'fee_breakdown_csv', process_fee_breakdown_rows, 'home')
        
    return render_template('import_fee_breakdown_csv.html', title='Import Fee Breakdown CSV')


def _process_fee_breakdown_csv_import(csv_reader):
    """Process fee breakdown CSV import."""
    stats = {'imported': 0, 'updated': 0, 'failed': 0}
    error_rows = []
    
    # Map column headers for dates
    date_column_map = {}
    if csv_reader.fieldnames:
        for field in csv_reader.fieldnames:
            if 'fee_paid_date' in field.lower():
                date_column_map['fee_paid_date'] = field
    
    existing_receipts = {fb.receipt_no for fb in FeeBreakdown.query.all()}
    
    batch_size = 100
    rows = list(csv_reader)
    
    for batch_start in range(0, len(rows), batch_size):
        batch_end = min(batch_start + batch_size, len(rows))
        current_batch = rows[batch_start:batch_end]
        
        try:
            with db.session.begin_nested():
                for row_index, row in enumerate(current_batch, start=batch_start+1):
                    try:
                        breakdown_data = _extract_fee_breakdown_data_from_row(row, date_column_map)
                        _validate_fee_breakdown_data(breakdown_data)
                        
                        # Check if student and fee record exist
                        student = Student.query.get(breakdown_data['pen_num'])
                        if not student:
                            raise ValueError(f"Student with PEN {breakdown_data['pen_num']} does not exist")
                            
                        fee_record = Fee.query.filter_by(
                            pen_num=breakdown_data['pen_num'], 
                            year=breakdown_data['year']
                        ).first()
                        if not fee_record:
                            raise ValueError(f"Fee record for PEN {breakdown_data['pen_num']}, Year {breakdown_data['year']} does not exist")

                        # Check transport fee validation
                        if breakdown_data['fee_type'] == 'Transport' and not fee_record.transport_used:
                            raise ValueError(f"Student with PEN {breakdown_data['pen_num']} has not opted in for Transport for Year {breakdown_data['year']}")

                        # Check for duplicate receipt numbers
                        _check_fee_breakdown_duplicates(breakdown_data, existing_receipts)

                        # Calculate correct due amount
                        calculated_due = _calculate_breakdown_due_from_fee_record(fee_record, breakdown_data)

                        existing_fee_breakdown = FeeBreakdown.query.filter_by(
                            pen_num=breakdown_data['pen_num'], 
                            year=breakdown_data['year'], 
                            fee_type=breakdown_data['fee_type'], 
                            term=breakdown_data['term'], 
                            payment_type=breakdown_data['payment_type']
                        ).first()

                        if existing_fee_breakdown:
                            _update_existing_fee_breakdown(existing_fee_breakdown, breakdown_data, calculated_due)
                            stats['updated'] += 1
                        else:
                            existing_receipts.add(breakdown_data['receipt_no'])
                            _create_new_fee_breakdown(breakdown_data, calculated_due)
                            stats['imported'] += 1

                    except Exception as e:
                        stats['failed'] += 1
                        error_rows.append(_create_fee_breakdown_error_row(row_index, str(e), row))
                        
            logger.info(f"Committed batch {batch_start//batch_size + 1}")
                    
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error processing batch {batch_start//batch_size + 1}: {str(e)}")
            error_rows.append(_create_fee_breakdown_batch_error_row(batch_start//batch_size + 1, str(e)))
    
    # Final commit
    try:
        if stats['imported'] > 0 or stats['updated'] > 0:
            db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed final commit: {str(e)}")
        error_rows.append(_create_fee_breakdown_final_error_row(str(e)))
    
    log_activity('imported', 'FeeBreakdown', 'BULK', 
                f"Imported {stats['imported']} fee payments, updated {stats['updated']} via CSV")
    
    if stats['failed'] > 0:
        error_rows.insert(0, _create_fee_breakdown_summary_error_row(stats))
        return generate_error_csv(error_rows, "fee_breakdown_import")
    else:
        flash(f"{stats['imported']} records imported, {stats['updated']} records updated successfully.", 'success')
        
    return None


def _extract_fee_breakdown_data_from_row(row, date_column_map):
    """Extract fee breakdown data from CSV row."""
    try:
        pen_num = int(str(row.get("pen_num", "0")).strip() or 0)
        year = int(str(row.get("year", "0")).strip() or 0)
        paid = float(str(row.get("paid", "0.0")).strip() or 0.0)
        due = float(str(row.get("due", "0.0")).strip() or 0.0)
        
        receipt_no_str = str(row.get("receipt_no", "")).strip()
        receipt_no = int(receipt_no_str) if receipt_no_str else None
    except ValueError as ve:
        raise ValueError(f"Invalid number format: {str(ve)}")
        
    fee_type = str(row.get("fee_type", "")).strip()
    term = str(row.get("term", "")).strip()
    payment_type = str(row.get("payment_type", "")).strip()
    
    fee_paid_date_str = str(row.get(date_column_map.get('fee_paid_date', 'fee_paid_date'), "")).strip()
    
    try:
        fee_paid_date = parse_date_from_string(fee_paid_date_str, 'fee_paid_date')
    except ValueError as ve:
        raise ValueError(f"Date parsing error: {str(ve)}")

    return {
        'pen_num': pen_num,
        'year': year,
        'fee_type': fee_type,
        'term': term,
        'payment_type': payment_type,
        'paid': paid,
        'due': due,
        'receipt_no': receipt_no,
        'fee_paid_date': fee_paid_date
    }


def _validate_fee_breakdown_data(breakdown_data):
    """Validate fee breakdown data."""
    if not breakdown_data['pen_num'] or breakdown_data['pen_num'] <= 0:
        raise ValueError("Invalid PEN Number")
    if not breakdown_data['year'] or breakdown_data['year'] <= 0:
        raise ValueError("Invalid year")
    if not breakdown_data['fee_type']:
        raise ValueError("Fee type is required")
    if not breakdown_data['term']:
        raise ValueError("Term is required")
    if not breakdown_data['payment_type']:
        raise ValueError("Payment type is required")
    if breakdown_data['paid'] < 0:
        raise ValueError("Paid amount cannot be negative")
    if not breakdown_data['receipt_no']:
        raise ValueError("Receipt number is required")


def _check_fee_breakdown_duplicates(breakdown_data, existing_receipts):
    """Check for duplicate fee breakdown receipts."""
    existing_receipt = FeeBreakdown.query.filter_by(receipt_no=breakdown_data['receipt_no']).first()
    existing_fee_breakdown = FeeBreakdown.query.filter_by(
        pen_num=breakdown_data['pen_num'], 
        year=breakdown_data['year'], 
        fee_type=breakdown_data['fee_type'], 
        term=breakdown_data['term'], 
        payment_type=breakdown_data['payment_type']
    ).first()
    
    if existing_receipt and not existing_fee_breakdown:
        raise ValueError(f"Receipt number {breakdown_data['receipt_no']} already exists for another payment")


def _calculate_breakdown_due_from_fee_record(fee_record, breakdown_data):
    """Calculate due amount from fee record."""
    terms_for_type = 1 if breakdown_data['fee_type'] == 'Application' else 3
    if breakdown_data['fee_type'] == 'Application':
        total_fee_for_type = fee_record.application_fee
    elif breakdown_data['fee_type'] == 'Transport':
        total_fee_for_type = fee_record.transport_fee - fee_record.transport_fee_concession
    elif breakdown_data['fee_type'] == 'School':
        total_fee_for_type = fee_record.school_fee - fee_record.school_fee_concession
    else:
        raise ValueError(f"Invalid fee type: {breakdown_data['fee_type']}")
        
    term_fee = total_fee_for_type / terms_for_type if terms_for_type > 0 else 0
    calculated_due = max(0, term_fee - breakdown_data['paid'])
    
    return calculated_due


def _update_existing_fee_breakdown(existing_fee_breakdown, breakdown_data, calculated_due):
    """Update existing fee breakdown record."""
    existing_fee_breakdown.paid = breakdown_data['paid']
    existing_fee_breakdown.due = calculated_due
    existing_fee_breakdown.receipt_no = breakdown_data['receipt_no']
    existing_fee_breakdown.fee_paid_date = breakdown_data['fee_paid_date']
    existing_fee_breakdown.updated_by = current_user.username


def _create_new_fee_breakdown(breakdown_data, calculated_due):
    """Create new fee breakdown record."""
    db.session.add(FeeBreakdown(
        pen_num=breakdown_data['pen_num'],
        year=breakdown_data['year'],
        fee_type=breakdown_data['fee_type'],
        term=breakdown_data['term'],
        payment_type=breakdown_data['payment_type'],
        paid=breakdown_data['paid'],
        due=calculated_due,
        receipt_no=breakdown_data['receipt_no'],
        fee_paid_date=breakdown_data['fee_paid_date'],
        created_by=current_user.username
    ))


def _create_fee_breakdown_error_row(row_index, error, row):
    """Create error row for fee breakdown import."""
    return {
        "Row": row_index,
        "Error": error,
        "PEN": row.get("pen_num", ""),
        "Year": row.get("year", ""),
        "Fee Type": row.get("fee_type", ""),
        "Receipt": row.get("receipt_no", "")
    }


def _create_fee_breakdown_batch_error_row(batch_num, error):
    """Create batch error row for fee breakdown."""
    return {
        "Row": f"Batch {batch_num}",
        "Error": f"Failed to commit batch: {error}",
        "PEN": "",
        "Year": "",
        "Fee Type": "",
        "Receipt": ""
    }


def _create_fee_breakdown_final_error_row(error):
    """Create final error row for fee breakdown."""
    return {
        "Row": "FINAL", 
        "Error": f"Failed final commit: {error}", 
        "PEN": "", 
        "Year": "",
        "Fee Type": "",
        "Receipt": ""
    }


def _create_fee_breakdown_summary_error_row(stats):
    """Create summary error row for fee breakdown."""
    return {
        "Row": "SUMMARY", 
        "Error": f"{stats['imported']} records imported, {stats['updated']} records updated, {stats['failed']} failed",
        "PEN": "",
        "Year": "",
        "Fee Type": "",
        "Receipt": ""
    }


# --- Data Viewing and Export ---
@report_bp.route("/view_table", methods=["GET", "POST"])
@login_required
def view_table():
    """View and filter table data."""
    form = TableSelectForm()
    table_name = request.args.get("table_name", None)
    
    data = None
    pagination = None
    start_date = None
    end_date = None
    pen_num = None

    # Retrieve session values if they exist
    start_date, end_date, pen_num = _get_session_filter_values()

    if request.method == "POST":
        table_name, start_date, end_date, pen_num = _process_table_filter_form()
        
    # Get model class based on table name
    if table_name:
        data, pagination = _get_table_data(table_name, start_date, end_date, pen_num)
            
    return render_template("view_table.html", 
                          data=data, 
                          pagination=pagination,
                          table_name=table_name, 
                          form=form,
                          start_date=start_date, 
                          end_date=end_date)


def _get_session_filter_values():
    """Get filter values from session."""
    start_date = None
    end_date = None
    pen_num = None
    
    start_date_str = session.get('start_date')
    end_date_str = session.get('end_date')
    pen_num_str = session.get('pen_num')

    if start_date_str:
        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        except ValueError:
            logger.warning(f"Invalid start_date in session: {start_date_str}")
            session.pop('start_date', None)
            
    if end_date_str:
        try:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
        except ValueError:
            logger.warning(f"Invalid end_date in session: {end_date_str}")
            session.pop('end_date', None)
            
    if pen_num_str:
        try:
            pen_num = int(pen_num_str)
        except ValueError:
            pen_num = None
    
    return start_date, end_date, pen_num


def _process_table_filter_form():
    """Process table filter form data."""
    table_name = request.form.get("table_select")
    start_date_str = request.form.get("start_date")
    end_date_str = request.form.get("end_date")
    pen_num_str = request.form.get("pen_num")
    
    start_date = None
    end_date = None
    pen_num = None
    
    # Process start and end dates
    if start_date_str:
        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
            session['start_date'] = start_date_str
        except ValueError:
            flash("Invalid start date format", "warning")
            session.pop('start_date', None)
    else:
        session.pop('start_date', None)
        
    if end_date_str:
        try:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
            session['end_date'] = end_date_str
        except ValueError:
            flash("Invalid end date format", "warning")
            session.pop('end_date', None)
    else:
        session.pop('end_date', None)
    
    # Process pen_num
    if table_name == 'transport':
        session.pop('pen_num', None)
        pen_num = None
    elif pen_num_str:
        try:
            pen_num = int(pen_num_str)
            session['pen_num'] = pen_num_str
        except ValueError:
            flash("Invalid PEN Number format. Please enter a valid number.", "warning")
            session.pop('pen_num', None)
            pen_num = None
    else:
        session.pop('pen_num', None)
        pen_num = None
    
    return table_name, start_date, end_date, pen_num


def _get_table_data(table_name, start_date, end_date, pen_num):
    """Get table data with filters."""
    models = {
        "student": Student,
        "classdetails": ClassDetails,
        "fee": Fee,
        "feebreakdown": FeeBreakdown,
        "transport": Transport
    }
    
    model = models.get(table_name)
    if model:
        try:
            query = model.query
            
            # Apply filters
            query = apply_date_filter(query, model, start_date, end_date)
            
            if pen_num and hasattr(model, 'pen_num'):
                query = query.filter(model.pen_num == pen_num)
            
            if hasattr(model, 'created_at'):
                query = query.order_by(model.created_at.desc())
            
            pagination = paginate_results(query)
            data = pagination.items
            
            log_activity('viewed', table_name, 'QUERY', 
                        f"Viewed {table_name} data with filters: " + 
                        (f"date range {start_date} to {end_date}" if start_date and end_date else "no date filter") + 
                        (f", PEN: {pen_num}" if pen_num else ""))
            
            return data, pagination
        except SQLAlchemyError as e:
            db.session.rollback()
            log_exception(e, "Database error retrieving table data")
            flash(f"Error retrieving data: {str(e)}", "danger")
    else:
        flash("Invalid table selected", "danger")
    
    return None, None


@report_bp.route("/export_csv/<table_name>", methods=["GET"])
@login_required
def export_csv(table_name):
    """Export table data as CSV file."""
    try:
        # Get filters from request args or session
        filters = _get_export_filters()
        
        # Define table configurations
        table_config = _get_table_export_config(table_name)
        if not table_config:
            return "Invalid table name", 400
        
        # Query data with filters
        data = _query_export_data(table_config, filters)
        
        log_activity('exported', table_name, 'CSV', 
                    f"Exported {table_name} data to CSV with filters: " + 
                    _format_filter_description(filters))
        
        return prepare_csv_response(data, table_config["fields"], table_name)
    except Exception as e:
        db.session.rollback()
        log_exception(e, "Error exporting CSV")
        flash(f"Error exporting data: {str(e)}", "danger")
        return redirect(url_for('report_bp.view_table'))


def _get_export_filters():
    """Get export filters from request or session."""
    start_date = None
    end_date = None
    pen_num = None
    
    start_date_str = request.args.get('start_date') or session.get('start_date')
    end_date_str = request.args.get('end_date') or session.get('end_date')
    pen_num_str = request.args.get('pen_num') or session.get('pen_num')

    if start_date_str:
        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
        except ValueError:
            flash("Invalid start date format", "warning")
            
    if end_date_str:
        try:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
        except ValueError:
            flash("Invalid end date format", "warning")
            
    if pen_num_str:
        try:
            pen_num = int(pen_num_str)
        except ValueError:
            flash("Invalid PEN Number format", "warning")
    
    return {
        'start_date': start_date,
        'end_date': end_date,
        'pen_num': pen_num
    }


def _get_table_export_config(table_name):
    """Get table export configuration."""
    table_configs = {
        "student": {
            "model": Student,
            "fields": ['pen_num', 'admission_number', 'aadhar_number', 'student_name', 'father_name', 
                    'mother_name', 'gender', 'date_of_birth', 'date_of_joining', 'contact_number', 
                    'village', 'created_at', 'created_by', 'updated_by']
        },
        "classdetails": {
            "model": ClassDetails,
            "fields": ['pen_num', 'year', 'current_class', 'section', 'roll_number', 'photo_id', 
                    'language', 'vocational', 'currently_enrolled', 'created_at', 'created_by', 'updated_by']
        },
        "fee": {
            "model": Fee,
            "fields": ['pen_num', 'year', 'school_fee', 'concession_reason', 'school_fee_concession',
                    'transport_used', 'application_fee', 'transport_fee', 'transport_fee_concession',
                    'transport_id', 'created_at', 'created_by', 'updated_by']
        },
        "feebreakdown": {
            "model": FeeBreakdown,
            "fields": ['pen_num', 'year', 'fee_type', 'term', 'payment_type', 'paid', 'due',
                    'receipt_no', 'fee_paid_date', 'created_at', 'created_by', 'updated_by']
        },
        "transport": {
            "model": Transport,
            "fields": ['transport_id', 'pick_up_point', 'route_number', 'created_at', 'created_by', 'updated_by']
        }
    }
    
    return table_configs.get(table_name)


def _query_export_data(table_config, filters):
    """Query data for export with filters."""
    model = table_config["model"]
    query = model.query
    query = apply_date_filter(query, model, filters['start_date'], filters['end_date'])
    
    if filters['pen_num'] and hasattr(model, 'pen_num'):
        query = query.filter(model.pen_num == filters['pen_num'])
    
    if hasattr(model, 'created_at'):
        query = query.order_by(model.created_at.desc())
        
    return query.all()


def _format_filter_description(filters):
    """Format filter description for logging."""
    parts = []
    if filters['start_date'] and filters['end_date']:
        parts.append(f"date range {filters['start_date']} to {filters['end_date']}")
    elif filters['start_date']:
        parts.append(f"from {filters['start_date']}")
    elif filters['end_date']:
        parts.append(f"to {filters['end_date']}")
    else:
        parts.append("no date filter")
        
    if filters['pen_num']:
        parts.append(f"PEN: {filters['pen_num']}")
    
    return ", ".join(parts)


@report_bp.route("/fee_summary_report", methods=["POST"])
@login_required
def fee_summary_report():
    """Generate fee summary report with filters."""
    try:
        # Get form data
        summary_filters = _extract_summary_filters()
        if summary_filters is None:
            return redirect(url_for('report_bp.view_table'))
        
        action = request.form.get('action', 'view')
        
        # Build the main query
        fee_summary_data = _build_fee_summary_query(summary_filters)
        
        # Log the activity
        filter_string = _format_summary_filter_string(summary_filters)
        log_activity('generated', 'FeeSummary', 'REPORT', 
                    f"Generated fee summary report with filters: {filter_string}")
        
        # Handle download action
        if action == 'download':
            return _generate_fee_summary_csv(fee_summary_data)
        
        # For view action, render the template with data
        form = TableSelectForm()
        return render_template("view_table.html", 
                              data=None,
                              pagination=None,
                              table_name=None, 
                              form=form,
                              fee_summary_data=fee_summary_data,
                              start_date=None, 
                              end_date=None)
        
    except SQLAlchemyError as e:
        db.session.rollback()
        log_exception(e, "Database error generating fee summary")
        flash("Error generating fee summary report. Please try again.", "danger")
        return redirect(url_for('report_bp.view_table'))
    except Exception as e:
        log_exception(e, "Error generating fee summary")
        flash("An error occurred while generating the report. Please try again.", "danger")
        return redirect(url_for('report_bp.view_table'))


def _extract_summary_filters():
    """Extract and validate summary filters from form."""
    summary_pen_num = request.form.get('summary_pen_num', '').strip()
    summary_class = request.form.get('summary_class', '').strip()
    summary_year = request.form.get('summary_year', '').strip()
    summary_start_date = request.form.get('summary_start_date', '').strip()
    summary_end_date = request.form.get('summary_end_date', '').strip()
    
    filters = {}
    
    if summary_pen_num:
        try:
            filters['pen_num'] = int(summary_pen_num)
        except ValueError:
            flash("Invalid PEN Number format", "warning")
            return None
            
    if summary_class:
        class_filter = summary_class.strip()
        if class_filter not in VALID_CLASSES:
            flash(f"Invalid Class. Must be one of: {', '.join(VALID_CLASSES)}", "warning")
            return None
        filters['class'] = class_filter
            
    if summary_year:
        try:
            filters['year'] = int(summary_year)
        except ValueError:
            flash("Invalid Year format", "warning")
            return None
            
    if summary_start_date:
        try:
            filters['start_date'] = datetime.strptime(summary_start_date, '%Y-%m-%d').date()
        except ValueError:
            flash("Invalid start date format", "warning")
            return None
            
    if summary_end_date:
        try:
            filters['end_date'] = datetime.strptime(summary_end_date, '%Y-%m-%d').date()
        except ValueError:
            flash("Invalid end date format", "warning")
            return None
    
    return filters


def _build_fee_summary_query(filters):
    """Build fee summary query with filters."""
    query = db.session.query(
        Student.pen_num,
        Student.student_name,
        ClassDetails.current_class,
        ClassDetails.section,
        Fee.year,
        func.coalesce(Fee.school_fee - Fee.school_fee_concession, 0).label('total_school_fee'),
        func.coalesce(Fee.transport_fee - Fee.transport_fee_concession, 0).label('total_transport_fee'),
        func.coalesce(Fee.application_fee, 0).label('total_application_fee'),
        func.coalesce(func.sum(
            case(
                (FeeBreakdown.fee_type == 'School', FeeBreakdown.paid),
                else_=0
            )
        ), 0).label('school_fee_paid'),
        func.coalesce(func.sum(
            case(
                (FeeBreakdown.fee_type == 'Transport', FeeBreakdown.paid),
                else_=0
            )
        ), 0).label('transport_fee_paid'),
        func.coalesce(func.sum(
            case(
                (FeeBreakdown.fee_type == 'Application', FeeBreakdown.paid),
                else_=0
            )
        ), 0).label('application_fee_paid')
    ).select_from(
        Student
    ).join(
        Fee, Student.pen_num == Fee.pen_num
    ).join(
        ClassDetails, (ClassDetails.pen_num == Student.pen_num) & (ClassDetails.year == Fee.year)
    ).outerjoin(
        FeeBreakdown, (FeeBreakdown.pen_num == Fee.pen_num) & (FeeBreakdown.year == Fee.year)
    )
    
    # Apply filters
    query = _apply_summary_filters(query, filters)
    
    # Group by to aggregate payments
    query = query.group_by(
        Student.pen_num,
        Student.student_name,
        ClassDetails.current_class,
        ClassDetails.section,
        Fee.year,
        Fee.school_fee,
        Fee.school_fee_concession,
        Fee.transport_fee,
        Fee.transport_fee_concession,
        Fee.application_fee
    ).order_by(Student.pen_num, Fee.year)
    
    # Execute query and calculate outstanding amounts
    raw_results = query.all()
    fee_summary_data = []
    
    for row in raw_results:
        total_fees = row.total_school_fee + row.total_transport_fee + row.total_application_fee
        total_paid = row.school_fee_paid + row.transport_fee_paid + row.application_fee_paid
        total_outstanding = max(0, total_fees - total_paid)
        
        fee_summary_data.append({
            'pen_num': row.pen_num,
            'student_name': row.student_name,
            'current_class': row.current_class,
            'section': row.section,
            'year': row.year,
            'total_school_fee': float(row.total_school_fee or 0),
            'total_transport_fee': float(row.total_transport_fee or 0),
            'total_application_fee': float(row.total_application_fee or 0),
            'school_fee_paid': float(row.school_fee_paid or 0),
            'transport_fee_paid': float(row.transport_fee_paid or 0),
            'application_fee_paid': float(row.application_fee_paid or 0),
            'total_outstanding': float(total_outstanding)
        })
    
    return fee_summary_data


def _apply_summary_filters(query, filters):
    """Apply filters to summary query."""
    if 'pen_num' in filters:
        query = query.filter(Student.pen_num == filters['pen_num'])
        
    if 'class' in filters:
        query = query.filter(ClassDetails.current_class == filters['class'])
        
    if 'year' in filters:
        query = query.filter(Fee.year == filters['year'])
        
    if 'start_date' in filters:
        query = query.filter(Fee.created_at >= filters['start_date'])
        
    if 'end_date' in filters:
        end_date_inclusive = filters['end_date'] + timedelta(days=1)
        query = query.filter(Fee.created_at < end_date_inclusive)
    
    return query


def _format_summary_filter_string(filters):
    """Format summary filter description."""
    filter_desc = []
    if 'pen_num' in filters:
        filter_desc.append(f"PEN: {filters['pen_num']}")
    if 'class' in filters:
        filter_desc.append(f"Class: {filters['class']}")
    if 'year' in filters:
        filter_desc.append(f"Year: {filters['year']}")
    if 'start_date' in filters:
        filter_desc.append(f"From: {filters['start_date']}")
    if 'end_date' in filters:
        filter_desc.append(f"To: {filters['end_date']}")
    
    return ", ".join(filter_desc) if filter_desc else "No filters"


def _generate_fee_summary_csv(fee_summary_data):
    """Generate CSV file for fee summary data."""
    output = StringIO()
    fieldnames = [
        'pen_num', 'student_name', 'class', 'year', 
        'total_school_fee', 'total_transport_fee', 'total_application_fee',
        'school_fee_paid', 'transport_fee_paid', 'application_fee_paid',
        'total_outstanding'
    ]
    
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    
    for row in fee_summary_data:
        csv_row = {
            'pen_num': row['pen_num'],
            'student_name': row['student_name'],
            'class': f"{row['current_class']}-{row['section']}",
            'year': row['year'],
            'total_school_fee': row['total_school_fee'],
            'total_transport_fee': row['total_transport_fee'],
            'total_application_fee': row['total_application_fee'],
            'school_fee_paid': row['school_fee_paid'],
            'transport_fee_paid': row['transport_fee_paid'],
            'application_fee_paid': row['application_fee_paid'],
            'total_outstanding': row['total_outstanding']
        }
        writer.writerow(csv_row)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f'fee_summary_report_{timestamp}.csv'
    
    response = Response(output.getvalue(), mimetype='text/csv')
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    response.headers['X-Filename'] = filename
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
