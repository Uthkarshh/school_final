from flask import render_template, flash, redirect, url_for, request, abort, session, Response
from school import app, db, bcrypt
from school.forms import (
    RegistrationForm, LoginForm, UpdateAccountForm, StudentForm, 
    ClassDetailsForm, FeeBreakdownForm, FeeForm, TransportForm, TableSelectForm
)
from school.models import User, Student, ClassDetails, Fee, FeeBreakdown, Transport, ActivityLog, parse_date_from_string
from flask_login import login_user, current_user, logout_user, login_required
from sqlalchemy.exc import IntegrityError
import csv
from io import TextIOWrapper, StringIO
from datetime import datetime, timedelta
from functools import wraps

# --- Utility Functions ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.user_role not in ['Admin', 'HR']:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def log_activity(action_type, entity_type, entity_id, description):
    """Log user activity to the activity_log table with IP address tracking"""
    if current_user.is_authenticated:
        activity = ActivityLog(
            user_id=current_user.id,
            action_type=action_type,
            entity_type=entity_type,
            entity_id=str(entity_id),
            description=description,
            ip_address=request.remote_addr
        )
        db.session.add(activity)
        db.session.commit()

def get_record_by_primary_key(model, **primary_keys):
    """Lookup a record by its primary key(s)"""
    try:
        return model.query.filter_by(**primary_keys).first()
    except:
        return None


def process_csv_import(request_files, file_key, process_row_func, redirect_url):
    """Generic CSV import processor with error handling and format detection"""
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
        csv_file = TextIOWrapper(file.stream, encoding='utf-8-sig')  # Handle UTF-8 with BOM
        csv_reader = csv.DictReader(csv_file)
        
        # Check if we have column headers with format specifications
        if csv_reader.fieldnames:
            print(f"CSV Headers: {csv_reader.fieldnames}")
        
        # Pass to the processing function
        return process_row_func(csv_reader)
    except Exception as e:
        flash(f'Error processing CSV file: {str(e)}', 'danger')
        print(f"CSV processing error: {str(e)}")
        import traceback
        traceback.print_exc()
    
    return redirect(url_for(redirect_url))


def apply_date_filter(query, model, start_date, end_date):
    """Apply date filters to a query"""
    if hasattr(model, 'created_at'):
        if start_date:
            query = query.filter(model.created_at >= start_date)
        if end_date:
            query = query.filter(model.created_at <= end_date + timedelta(days=1))
    return query


def prepare_csv_response(data, fieldnames, table_name):
    """Create a CSV response from data"""
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    
    for item in data:
        row = {field: getattr(item, field, '') for field in fieldnames}
        writer.writerow(row)
    
    response = Response(output.getvalue(), mimetype='text/csv')
    filename = f'{table_name}_{datetime.now().strftime("%Y%m%d")}.csv'
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    response.headers['X-Filename'] = filename
    return response

@app.template_filter('datetime')
def format_datetime(value):
    if isinstance(value, str):
        try:
            value = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        except:
            return value
    
    # For "today" timestamps
    today = datetime.now().date()
    if value.date() == today:
        return f"Today at {value.strftime('%I:%M %p')}"
    
    # For "yesterday" timestamps
    yesterday = today - timedelta(days=1)
    if value.date() == yesterday:
        return f"Yesterday at {value.strftime('%I:%M %p')}"
    
    # For older timestamps
    days_diff = (today - value.date()).days
    if days_diff < 7:
        return f"{days_diff} days ago"
    else:
        return value.strftime('%b %d, %Y')


# --- Route Definitions ---
@app.route("/")
@app.route("/home")
def home():
    pages = [
        {"name": "Dashboard", "relative_path": url_for('home')},
        {"name": "Students", "relative_path": url_for('student_form')},
        {"name": "Classes", "relative_path": url_for('class_details_form')},
        {"name": "Fees", "relative_path": url_for('fee_form')},
        {"name": "Transport", "relative_path": url_for('transport_form')},
        {"name": "Reports", "relative_path": url_for('view_table')},
        {"name": "Users", "relative_path": url_for('admin_users') if current_user.is_authenticated and current_user.user_role == 'Admin' else "#"},
        {"name": "Profile", "relative_path": url_for('account')},
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
        # Basic stats
        stats['student_count'] = Student.query.count()
        stats['fee_collection'] = db.session.query(db.func.sum(FeeBreakdown.paid)).scalar() or 0
        stats['transport_routes'] = db.session.query(db.func.count(db.distinct(Transport.route_number))).scalar() or 0
        stats['pending_fees'] = FeeBreakdown.query.filter(FeeBreakdown.due > 0).count()
      
        # If you've created the ActivityLog model, fetch recent activities
        if 'ActivityLog' in globals():
            recent_activities = ActivityLog.query.order_by(
                ActivityLog.created_at.desc()
            ).limit(5).all()
        else:
            # Fallback to using created_at and updated_by from various tables
            # Get recent student records
            student_activities = []
            for student in Student.query.order_by(Student.created_at.desc()).limit(3):
                student_activities.append({
                    'action_type': 'added',
                    'entity_type': 'Student',
                    'description': f"Added student: {student.student_name}",
                    'user': {'username': student.created_by},
                    'created_at': student.created_at
                })
            
            # Get recent fee payments
            fee_activities = []
            for fee in FeeBreakdown.query.order_by(FeeBreakdown.created_at.desc()).limit(3):
                fee_activities.append({
                    'action_type': 'added',
                    'entity_type': 'Fee',
                    'description': f"Fee payment of ₹{float(fee.paid)} received for PEN {fee.pen_num}",
                    'user': {'username': fee.created_by},
                    'created_at': fee.created_at
                })
            
            # Combine and sort activities
            all_activities = student_activities + fee_activities
            recent_activities = sorted(all_activities, key=lambda x: x['created_at'], reverse=True)[:5]

    return render_template("home.html", pages=pages, stats=stats, recent_activities=recent_activities)


@app.route("/about")
@login_required
def about():
    return render_template("about.html", title="About me")

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        first_user = User.query.count() == 0
        
        user = User(
            username=form.username.data,
            email=form.email.data,
            user_role='Admin' if first_user else form.user_role.data,
            password=hashed_password,
            is_approved=first_user
        )
        
        db.session.add(user)
        db.session.commit()

        if first_user:
            flash('Your admin account has been automatically approved. You can now log in.', 'info')
            flash('Admin role set automatically.', 'info')
            log_activity('added', 'User', user.id, f"First admin account created: {user.username}")
        else:
            flash('Your registration is pending admin approval. You will be notified once your account is approved.', 'info')
            flash('User role will be reviewed by admin.', 'info')
            
        return redirect(url_for('login'))

    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
        
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            if user.is_approved:
                login_user(user, remember=form.remember.data)
                log_activity('login', 'User', user.id, f"User logged in: {user.username}")
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('home'))
            else:
                flash('Your account is pending admin approval. Please wait for approval.', 'warning')
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
            
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
def logout():
    if current_user.is_authenticated:
        log_activity('logout', 'User', current_user.id, f"User logged out: {current_user.username}")
    logout_user()
    return redirect(url_for('home'))

@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        old_username = current_user.username
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        log_activity('updated', 'User', current_user.id, f"User profile updated: {old_username} → {current_user.username}")
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
        
    return render_template('account.html', title='Account', form=form)

# --- Admin User Management ---
@app.route("/admin/users")
@login_required
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin_users.html', users=users, title='Admin - User Management')

@app.route("/admin/users/toggle_approve/<int:user_id>")
@login_required
@admin_required
def toggle_user_approval(user_id):
    user = User.query.get_or_404(user_id)
    user.is_approved = not user.is_approved
    db.session.commit()

    action = "approved" if user.is_approved else "access revoked"
    log_activity('updated', 'User', user.id, f"User {action}: {user.username}")
    
    flash_message = f'User {user.username} has been {action}.'
    flash_category = 'success' if user.is_approved else 'warning'
    flash(flash_message, flash_category)

    return redirect(url_for('admin_users'))

@app.route("/admin/users/reject/<int:user_id>")
@login_required
@admin_required
def reject_user(user_id):
    user = User.query.get_or_404(user_id)
    username = user.username
    db.session.delete(user)
    db.session.commit()
    log_activity('deleted', 'User', user_id, f"User rejected and deleted: {username}")
    flash(f'User {username} has been rejected and deleted.', 'danger')
    return redirect(url_for('admin_users'))

@app.route("/admin/users/bulk_approve")
@login_required
@admin_required
def bulk_approve_users():
    user_ids = request.args.get('ids', '')
    if not user_ids:
        flash('No users selected', 'warning')
        return redirect(url_for('admin_users'))
    
    id_list = [int(id) for id in user_ids.split(',') if id.isdigit()]
    
    if not id_list:
        flash('Invalid user selection', 'warning')
        return redirect(url_for('admin_users'))
    
    users = User.query.filter(User.id.in_(id_list)).all()
    approved_count = 0
    
    for user in users:
        if not user.is_approved:
            user.is_approved = True
            approved_count += 1
            log_activity('updated', 'User', user.id, f"User approved in bulk operation: {user.username}")
    
    db.session.commit()
    
    if approved_count > 0:
        flash(f'Successfully approved {approved_count} users', 'success')
    else:
        flash('No users needed approval', 'info')
    
    return redirect(url_for('admin_users'))

@app.route("/admin/users/bulk_reject")
@login_required
@admin_required
def bulk_reject_users():
    user_ids = request.args.get('ids', '')
    if not user_ids:
        flash('No users selected', 'warning')
        return redirect(url_for('admin_users'))
    
    id_list = [int(id) for id in user_ids.split(',') if id.isdigit()]
    
    if not id_list:
        flash('Invalid user selection', 'warning')
        return redirect(url_for('admin_users'))
    
    users = User.query.filter(User.id.in_(id_list)).all()
    deleted_count = 0
    
    for user in users:
        username = user.username
        user_id = user.id
        db.session.delete(user)
        deleted_count += 1
        log_activity('deleted', 'User', user_id, f"User rejected in bulk operation: {username}")
    
    db.session.commit()
    
    flash(f'Successfully deleted {deleted_count} users', 'success')
    return redirect(url_for('admin_users'))

# --- Student Management ---
@app.route("/student_form", methods=['GET', 'POST'])
@login_required
@admin_required
def student_form():
    # Check if we're in edit mode with a pen_num
    edit_pen_num = request.args.get('edit_pen_num')
    student = None
    
    if edit_pen_num:
        # Try to fetch the student record
        try:
            student = Student.query.get(int(edit_pen_num))
        except:
            flash('Invalid PEN Number specified for editing', 'danger')
    
    form = StudentForm()
    
    # Populate form with existing data if editing
    if student and request.method == 'GET':
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
    
    if form.validate_on_submit():
        # Check if we're updating an existing record
        existing_student = Student.query.get(form.pen_num.data)
        
        if existing_student:
            # Update existing record
            existing_student.admission_number = form.admission_number.data
            existing_student.aadhar_number = form.aadhar_number.data
            existing_student.student_name = form.student_name.data
            existing_student.father_name = form.father_name.data
            existing_student.mother_name = form.mother_name.data
            existing_student.gender = form.gender.data
            existing_student.date_of_birth = form.date_of_birth.data
            existing_student.date_of_joining = form.date_of_joining.data
            existing_student.contact_number = form.contact_number.data
            existing_student.village = form.village.data
            existing_student.updated_by = current_user.username
            
            db.session.commit()
            log_activity('updated', 'Student', form.pen_num.data, 
                        f"Updated student record: {form.student_name.data}")
            flash('Student record updated successfully!', 'success')
        else:
            # Create new record
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
            db.session.commit()
            log_activity('added', 'Student', form.pen_num.data, 
                        f"Added new student: {form.student_name.data}")
            flash('Student record added successfully!', 'success')
            
        return redirect(url_for('student_form'))
        
    return render_template('student_form.html', title='Student Form', form=form, student=student)


@app.route("/import_student_csv", methods=['GET', 'POST'])
@login_required
@admin_required
def import_student_csv():
    if request.method == 'POST':
        def process_student_rows(csv_reader):
            stats = {'imported': 0, 'updated': 0, 'failed': 0}
            
            # Map column headers that might include format specifications
            date_column_map = {}
            if csv_reader.fieldnames:
                for field in csv_reader.fieldnames:
                    # Check if this is a date field with format specification
                    if 'date_of_birth' in field.lower():
                        date_column_map['date_of_birth'] = field
                    elif 'date_of_joining' in field.lower():
                        date_column_map['date_of_joining'] = field
            
            for row in csv_reader:
                try:
                    # Process data with safe type conversion
                    try:
                        pen_num = int(str(row.get("pen_num", "0")).strip() or 0)
                        admission_number = int(str(row.get("admission_number", "0")).strip() or 0)
                        aadhar_number = int(str(row.get("aadhar_number", "0")).strip() or 0)
                    except ValueError as ve:
                        raise ValueError(f"Invalid number format: {str(ve)}")
                        
                    student_name = str(row.get("student_name", "")).strip()
                    father_name = str(row.get("father_name", "")).strip()
                    mother_name = str(row.get("mother_name", "")).strip()
                    gender = str(row.get("gender", "")).strip()
                    contact_number = str(row.get("contact_number", "")).strip()
                    village = str(row.get("village", "")).strip()
                    
                    # Get date values using the mapped column names
                    date_of_birth_str = str(row.get(date_column_map.get('date_of_birth', 'date_of_birth'), "")).strip()
                    date_of_joining_str = str(row.get(date_column_map.get('date_of_joining', 'date_of_joining'), "")).strip()
                    
                    # Parse dates with the specified format in the header (mm.dd.yyyy)
                    date_of_birth = None
                    date_of_joining = None
                    
                    if date_of_birth_str:
                        try:
                            date_of_birth = datetime.strptime(date_of_birth_str, '%d.%m.%Y').date()
                        except ValueError:
                            try:
                                # Try alternate format
                                date_of_birth = datetime.strptime(date_of_birth_str, '%m.%d.%Y').date()
                            except ValueError:
                                raise ValueError(f"Invalid date format for date_of_birth: {date_of_birth_str}")
                    else:
                        # Use a default date if one is not provided
                        date_of_birth = datetime(2000, 1, 1).date()
                    
                    if date_of_joining_str:
                        try:
                            date_of_joining = datetime.strptime(date_of_joining_str, '%d.%m.%Y').date()
                        except ValueError:
                            try:
                                # Try alternate format
                                date_of_joining = datetime.strptime(date_of_joining_str, '%m.%d.%Y').date()
                            except ValueError:
                                raise ValueError(f"Invalid date format for date_of_joining: {date_of_joining_str}")
                    else:
                        # Use a default date if one is not provided
                        date_of_joining = datetime.now().date()

                    # Basic validation
                    if not pen_num or not admission_number or not student_name:
                        raise ValueError("Missing required student details")

                    # Check for existing record
                    existing_student = Student.query.filter_by(pen_num=pen_num).first()

                    if existing_student:
                        # Update existing record
                        existing_student.admission_number = admission_number
                        existing_student.aadhar_number = aadhar_number
                        existing_student.student_name = student_name
                        existing_student.father_name = father_name
                        existing_student.mother_name = mother_name
                        existing_student.gender = gender
                        existing_student.date_of_birth = date_of_birth
                        existing_student.date_of_joining = date_of_joining
                        existing_student.contact_number = contact_number
                        existing_student.village = village
                        existing_student.updated_by = current_user.username
                        stats['updated'] += 1
                    else:
                        # Create new record
                        db.session.add(Student(
                            pen_num=pen_num,
                            admission_number=admission_number,
                            aadhar_number=aadhar_number,
                            student_name=student_name,
                            father_name=father_name,
                            mother_name=mother_name,
                            gender=gender,
                            date_of_birth=date_of_birth,
                            date_of_joining=date_of_joining,
                            contact_number=contact_number,
                            village=village,
                            created_by=current_user.username
                        ))
                        stats['imported'] += 1

                    # Periodically flush to reduce memory usage
                    if (stats['imported'] + stats['updated']) % 100 == 0:
                        db.session.flush()
                        
                except Exception as e:
                    db.session.rollback()
                    flash(f"Error in row {stats['imported'] + stats['updated'] + stats['failed'] + 1}: {str(e)}", "danger")
                    stats['failed'] += 1
                    
            # Final commit
            try:
                db.session.commit()
                log_activity('imported', 'Student', 'BULK', 
                            f"Imported {stats['imported']} students, updated {stats['updated']} records via CSV")
                flash(f"{stats['imported']} records imported, {stats['updated']} records updated, {stats['failed']} records failed.", 'success')
            except Exception as e:
                db.session.rollback()
                flash(f"Database error during commit: {str(e)}", "danger")
                
            return redirect(url_for('home'))
            
        return process_csv_import(request.files, 'student_csv', process_student_rows, 'home')
        
    return render_template('import_student_csv.html', title='Import Student CSV')

# --- Transport Management ---
@app.route("/transport_form", methods=['GET', 'POST'])
@login_required
@admin_required
def transport_form():
    form = TransportForm()
    if form.validate_on_submit():
        transport = Transport(
            pick_up_point=form.pick_up_point.data,
            route_number=form.route_number.data,
            created_by=current_user.username
        )
        db.session.add(transport)
        db.session.commit()
        log_activity('added', 'Transport', transport.transport_id, 
                    f"Added transport route #{form.route_number.data} for {form.pick_up_point.data}")
        flash('Transport record added successfully!', 'success')
        return redirect(url_for('transport_form'))
        
    return render_template('transport_form.html', title='Transport Form', form=form)

@app.route("/import_transport_csv", methods=['GET', 'POST'])
@login_required
@admin_required
def import_transport_csv():
    if request.method == 'POST':
        def process_transport_rows(csv_reader):
            stats = {'imported': 0, 'failed': 0}
            
            # Track existing pick-up points to avoid duplicates
            existing_pick_up_points = {t.pick_up_point.lower() for t in Transport.query.all()}
            
            for row in csv_reader:
                try:
                    pick_up_point = str(row.get("pick_up_point", "")).strip()
                    
                    try:
                        route_number = int(str(row.get("route_number", "")).strip() or 0)
                    except ValueError:
                        raise ValueError("Invalid route number format")

                    if not pick_up_point or not route_number:
                        raise ValueError("Missing required transport details")
                        
                    # Check for duplicate pick-up points (case insensitive)
                    if pick_up_point.lower() in existing_pick_up_points:
                        flash(f"Pick-up point '{pick_up_point}' already exists - skipping", "warning")
                        continue

                    db.session.add(Transport(
                        pick_up_point=pick_up_point,
                        route_number=route_number,
                        created_by=current_user.username
                    ))
                    stats['imported'] += 1
                    existing_pick_up_points.add(pick_up_point.lower())

                    # Periodic flush
                    if stats['imported'] % 100 == 0:
                        db.session.flush()

                except Exception as e:
                    flash(f"Error in row {stats['imported'] + stats['failed'] + 1}: {str(e)}", "danger")
                    stats['failed'] += 1
                    
            # Final commit
            try:
                db.session.commit()
                log_activity('imported', 'Transport', 'BULK', 
                            f"Imported {stats['imported']} transport routes via CSV")
                flash(f"{stats['imported']} transport records imported, {stats['failed']} records failed.", 'success')
            except Exception as e:
                db.session.rollback()
                flash(f"Database error during commit: {str(e)}", "danger")
                
            return redirect(url_for('home'))

            
        return process_csv_import(request.files, 'transport_csv', process_transport_rows, 'home')
        
    return render_template('import_transport_csv.html', title='Import Transport CSV')

# --- Class Details Management ---
@app.route("/class_details_form", methods=['GET', 'POST'])
@login_required
@admin_required
def class_details_form():
    # Check if we're in edit mode
    edit_pen_num = request.args.get('edit_pen_num')
    edit_year = request.args.get('edit_year')
    class_details = None
    
    if edit_pen_num and edit_year:
        # Try to fetch the record
        try:
            class_details = ClassDetails.query.filter_by(
                pen_num=int(edit_pen_num), 
                year=int(edit_year)
            ).first()
        except:
            flash('Invalid parameters specified for editing', 'danger')
    
    form = ClassDetailsForm()
    
    # Populate form with existing data if editing
    if class_details and request.method == 'GET':
        form.pen_num.data = class_details.pen_num
        form.year.data = class_details.year
        form.current_class.data = class_details.current_class
        form.section.data = class_details.section
        form.roll_number.data = class_details.roll_number
        form.photo_id.data = class_details.photo_id
        form.language.data = class_details.language
        form.vocational.data = class_details.vocational
        form.currently_enrolled.data = class_details.currently_enrolled
    
    if form.validate_on_submit():
        # Check if record exists
        existing_record = ClassDetails.query.filter_by(
            pen_num=form.pen_num.data, 
            year=form.year.data
        ).first()
        
        if existing_record:
            # Update existing record
            existing_record.current_class = form.current_class.data
            existing_record.section = form.section.data
            existing_record.roll_number = form.roll_number.data
            existing_record.photo_id = form.photo_id.data
            existing_record.language = form.language.data
            existing_record.vocational = form.vocational.data
            existing_record.currently_enrolled = form.currently_enrolled.data
            existing_record.updated_by = current_user.username
            
            db.session.commit()
            
            # Get student name for activity log
            student = Student.query.get(form.pen_num.data)
            student_name = student.student_name if student else "Unknown"
            
            log_activity('updated', 'ClassDetails', f"{form.pen_num.data}-{form.year.data}", 
                        f"Updated class details for student: {student_name}, Class: {form.current_class.data}-{form.section.data}")
            
            flash('Class details updated successfully!', 'success')
        else:
            # Create new record
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
            db.session.commit()
            
            # Get student name for activity log
            student = Student.query.get(form.pen_num.data)
            student_name = student.student_name if student else "Unknown"
            
            log_activity('added', 'ClassDetails', f"{form.pen_num.data}-{form.year.data}", 
                        f"Added class details for student: {student_name}, Class: {form.current_class.data}-{form.section.data}")
            
            flash('Class details added successfully!', 'success')
            
        return redirect(url_for('home'))
        
    return render_template('class_details_form.html', title='Class Details', form=form, class_details=class_details)


@app.route("/import_class_details_csv", methods=['GET', 'POST'])
@login_required
@admin_required
def import_class_details_csv():
    if request.method == 'POST':
        def process_class_details_rows(csv_reader):
            stats = {'imported': 0, 'updated': 0, 'failed': 0}
            
            for row in csv_reader:
                try:
                    # Process data with safe type conversion
                    try:
                        pen_num = int(str(row.get("pen_num", "0")).strip() or 0)
                        year = int(str(row.get("year", "0")).strip() or 0)
                        current_class = int(str(row.get("current_class", "0")).strip() or 0)
                        roll_number = int(str(row.get("roll_number", "0")).strip() or 0)
                        photo_id = int(str(row.get("photo_id", "0")).strip() or 0)
                    except ValueError as ve:
                        raise ValueError(f"Invalid number format: {str(ve)}")
                        
                    section = str(row.get("section", "")).strip()
                    language = str(row.get("language", "")).strip()
                    vocational = str(row.get("vocational", "")).strip()
                    
                    # Boolean conversion
                    currently_enrolled_str = str(row.get("currently_enrolled", "")).strip().lower()
                    currently_enrolled = currently_enrolled_str in ["true", "1", "yes", "y", "t"]

                    # Basic validation
                    if not pen_num or not year or not current_class:
                        raise ValueError("Missing required class details")

                    # Check if student exists
                    student = Student.query.get(pen_num)
                    if not student:
                        raise ValueError(f"Student with PEN {pen_num} does not exist")

                    # Check if record exists
                    existing_record = ClassDetails.query.filter_by(pen_num=pen_num, year=year).first()

                    if existing_record:
                        # Update existing record
                        existing_record.current_class = current_class
                        existing_record.section = section
                        existing_record.roll_number = roll_number
                        existing_record.photo_id = photo_id
                        existing_record.language = language
                        existing_record.vocational = vocational
                        existing_record.currently_enrolled = currently_enrolled
                        existing_record.updated_by = current_user.username
                        stats['updated'] += 1
                    else:
                        # Insert new record
                        db.session.add(ClassDetails(
                            pen_num=pen_num,
                            year=year,
                            current_class=current_class,
                            section=section,
                            roll_number=roll_number,
                            photo_id=photo_id,
                            language=language,
                            vocational=vocational,
                            currently_enrolled=currently_enrolled,
                            created_by=current_user.username
                        ))
                        stats['imported'] += 1

                    # Periodic flush
                    if (stats['imported'] + stats['updated']) % 100 == 0:
                        db.session.flush()

                except Exception as e:
                    db.session.rollback()
                    flash(f"Error in row {stats['imported'] + stats['updated'] + stats['failed'] + 1}: {str(e)}", "danger")
                    stats['failed'] += 1
                    
            # Final commit
            try:
                db.session.commit()
                log_activity('imported', 'ClassDetails', 'BULK', 
                            f"Imported {stats['imported']} class records, updated {stats['updated']} via CSV")
                flash(f"{stats['imported']} records imported, {stats['updated']} records updated, {stats['failed']} records failed.", 'success')
            except Exception as e:
                db.session.rollback()
                flash(f"Database error during commit: {str(e)}", "danger")
                
            return redirect(url_for('home'))
        return process_csv_import(request.files, 'class_details_csv', process_class_details_rows, 'home')
        
    return render_template('import_class_details_csv.html', title='Import Class Details CSV')

# --- Fee Management ---
@app.route("/fee_form", methods=['GET', 'POST'])
@login_required
@admin_required
def fee_form():
    # Check if we're in edit mode
    edit_pen_num = request.args.get('edit_pen_num')
    edit_year = request.args.get('edit_year')
    fee_record = None
    
    if edit_pen_num and edit_year:
        # Try to fetch the record
        try:
            fee_record = Fee.query.filter_by(
                pen_num=int(edit_pen_num), 
                year=int(edit_year)
            ).first()
        except:
            flash('Invalid parameters specified for editing', 'danger')
    
    form = FeeForm()
    
    # Populate form with existing data if editing
    if fee_record and request.method == 'GET':
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
    
    if form.validate_on_submit():
        transport_used = form.transport_used.data
        transport_id = None
        transport_fee = 0
        transport_fee_concession = 0
        
        if transport_used:
            pick_up_point = form.pick_up_point.data
            transport = Transport.query.filter_by(pick_up_point=pick_up_point).first()
            transport_id = transport.transport_id if transport else None
            transport_fee = form.transport_fee.data
            transport_fee_concession = form.transport_fee_concession.data

        # Check if record exists
        existing_fee = Fee.query.filter_by(
            pen_num=form.pen_num.data, 
            year=form.year.data
        ).first()
        
        # Get student name for activity log
        student = Student.query.get(form.pen_num.data)
        student_name = student.student_name if student else "Unknown"
        
        if existing_fee:
            # Update existing record
            existing_fee.school_fee = form.school_fee.data
            existing_fee.concession_reason = form.concession_reason.data
            existing_fee.transport_used = transport_used
            existing_fee.application_fee = form.application_fee.data
            existing_fee.transport_fee = transport_fee
            existing_fee.transport_fee_concession = transport_fee_concession
            existing_fee.transport_id = transport_id
            existing_fee.updated_by = current_user.username
            
            db.session.commit()
            
            log_activity('updated', 'Fee', f"{form.pen_num.data}-{form.year.data}", 
                        f"Updated fee record for student: {student_name}, Year: {form.year.data}")
            
            flash('Fee record updated successfully!', 'success')
        else:
            # Create new record
            fee = Fee(
                pen_num=form.pen_num.data,
                year=form.year.data,
                school_fee=form.school_fee.data,
                concession_reason=form.concession_reason.data,
                transport_used=transport_used,
                application_fee=form.application_fee.data,
                transport_fee=transport_fee,
                transport_fee_concession=transport_fee_concession,
                transport_id=transport_id,
                created_by=current_user.username
            )
            db.session.add(fee)
            db.session.commit()
            
            log_activity('added', 'Fee', f"{form.pen_num.data}-{form.year.data}", 
                        f"Added fee record for student: {student_name}, Year: {form.year.data}")
            
            flash('Fee record added successfully!', 'success')
            
        return redirect(url_for('home'))
        
    return render_template('fee_form.html', title='Fee Form', form=form, fee_record=fee_record)

@app.route("/import_fee_csv", methods=['GET', 'POST'])
@login_required
@admin_required
def import_fee_csv():
    if request.method == 'POST':
        def process_fee_rows(csv_reader):
            stats = {'imported': 0, 'updated': 0, 'failed': 0}
            
            # Prefetch transport data to reduce database queries
            transports = {t.pick_up_point: t.transport_id for t in Transport.query.all()}
            
            for row in csv_reader:
                try:
                    # Process data with safe type conversion
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
                    
                    # Boolean conversion
                    transport_used_str = str(row.get("transport_used", "")).strip().lower()
                    transport_used = transport_used_str in ["true", "1", "yes", "y", "t"]
                    
                    pick_up_point = str(row.get("pick_up_point", "")).strip()

                    # Basic validation
                    if not pen_num or not year:
                        raise ValueError("Missing required fee details")

                    # Check if student exists
                    student = Student.query.get(pen_num)
                    if not student:
                        raise ValueError(f"Student with PEN {pen_num} does not exist")

                    # Get transport_id from prefetched data
                    transport_id = transports.get(pick_up_point) if transport_used and pick_up_point else None
                    
                    if transport_used and not transport_id and pick_up_point:
                        # If the pick-up point doesn't exist but is needed, create it
                        new_transport = Transport(
                            pick_up_point=pick_up_point,
                            route_number=int(str(row.get("route_number", "0")).strip() or 0),
                            created_by=current_user.username
                        )
                        db.session.add(new_transport)
                        db.session.flush()  # Get the ID immediately
                        transport_id = new_transport.transport_id
                        transports[pick_up_point] = transport_id  # Update cache
                    
                    if not transport_used:
                        transport_id = None
                        transport_fee = 0
                        transport_fee_concession = 0

                    # Check if record exists
                    existing_fee = Fee.query.filter_by(pen_num=pen_num, year=year).first()

                    if existing_fee:
                        # Update existing record
                        existing_fee.school_fee = school_fee
                        existing_fee.concession_reason = concession_reason
                        existing_fee.transport_used = transport_used
                        existing_fee.application_fee = application_fee
                        existing_fee.transport_fee = transport_fee
                        existing_fee.transport_fee_concession = transport_fee_concession
                        existing_fee.transport_id = transport_id
                        existing_fee.updated_by = current_user.username
                        stats['updated'] += 1
                    else:
                        # Insert new record
                        db.session.add(Fee(
                            pen_num=pen_num,
                            year=year,
                            school_fee=school_fee,
                            concession_reason=concession_reason,
                            transport_used=transport_used,
                            application_fee=application_fee,
                            transport_fee=transport_fee,
                            transport_fee_concession=transport_fee_concession,
                            transport_id=transport_id,
                            created_by=current_user.username
                        ))
                        stats['imported'] += 1

                    # Periodic flush
                    if (stats['imported'] + stats['updated']) % 100 == 0:
                        db.session.flush()

                except Exception as e:
                    db.session.rollback()
                    flash(f"Error in row {stats['imported'] + stats['updated'] + stats['failed'] + 1}: {str(e)}", "danger")
                    stats['failed'] += 1
                    
            # Final commit
            try:
                db.session.commit()
                log_activity('imported', 'Fee', 'BULK', 
                            f"Imported {stats['imported']} fee records, updated {stats['updated']} via CSV")
                flash(f"{stats['imported']} records imported, {stats['updated']} records updated, {stats['failed']} records failed.", 'success')
            except Exception as e:
                db.session.rollback()
                flash(f"Database error during commit: {str(e)}", "danger")
                
            return redirect(url_for('home'))
            
        return process_csv_import(request.files, 'fee_csv', process_fee_rows, 'home')
        
    return render_template('import_fee_csv.html', title='Import Fee CSV')

@app.route("/fee_breakdown_form", methods=['GET', 'POST'])
@login_required
@admin_required
def fee_breakdown_form():
    # Check if we're in edit mode
    edit_pen_num = request.args.get('edit_pen_num')
    edit_year = request.args.get('edit_year')
    edit_fee_type = request.args.get('edit_fee_type')
    edit_term = request.args.get('edit_term')
    edit_payment_type = request.args.get('edit_payment_type')
    fee_breakdown = None
    
    if edit_pen_num and edit_year and edit_fee_type and edit_term and edit_payment_type:
        # Try to fetch the record
        try:
            fee_breakdown = FeeBreakdown.query.filter_by(
                pen_num=int(edit_pen_num),
                year=int(edit_year),
                fee_type=edit_fee_type,
                term=edit_term,
                payment_type=edit_payment_type
            ).first()
        except:
            flash('Invalid parameters specified for editing', 'danger')
    
    form = FeeBreakdownForm()
    
    # Populate form with existing data if editing
    if fee_breakdown and request.method == 'GET':
        form.pen_num.data = fee_breakdown.pen_num
        form.year.data = fee_breakdown.year
        form.fee_type.data = fee_breakdown.fee_type
        form.term.data = fee_breakdown.term
        form.payment_type.data = fee_breakdown.payment_type
        form.paid.data = fee_breakdown.paid
        form.receipt_no.data = fee_breakdown.receipt_no
        form.fee_paid_date.data = fee_breakdown.fee_paid_date
    
    if form.validate_on_submit():
        pen_num = form.pen_num.data
        year = form.year.data
        fee_type = form.fee_type.data
        term = form.term.data
        payment_type = form.payment_type.data

        # Check if we have a fee record first
        fee_record = Fee.query.filter_by(pen_num=pen_num, year=year).first()
        if not fee_record:
            flash(f'Fee record not found for PEN Number: {pen_num} and Year: {year}. Please add fee details first.', 'danger')
            return render_template('fee_breakdown_form.html', title='Fee Breakdown', form=form, fee_breakdown=fee_breakdown)

        # Get student name for activity log
        student = Student.query.get(pen_num)
        student_name = student.student_name if student else "Unknown"

        # Calculate term fee amount
        terms_for_type = 1 if fee_type == 'Application' else 3
        
        if fee_type == 'Application':
            total_fee_for_type = fee_record.application_fee
        elif fee_type == 'Transport':
            if fee_record.transport_used:
                total_fee_for_type = fee_record.transport_fee - fee_record.transport_fee_concession
            else:
                flash(f'Student with PEN Number: {pen_num} hasn\'t opted in for Transport for Year: {year}', 'danger')
                return render_template('fee_breakdown_form.html', title='Fee Breakdown', form=form, fee_breakdown=fee_breakdown)
        elif fee_type == 'School':
            total_fee_for_type = fee_record.school_fee - fee_record.school_fee_concession
            
        term_fee = total_fee_for_type / terms_for_type if terms_for_type > 0 else 0
        calculated_due = term_fee - form.paid.data

        # Check if record exists
        existing_fee_breakdown = FeeBreakdown.query.filter_by(
            pen_num=pen_num,
            year=year,
            fee_type=fee_type,
            term=term,
            payment_type=payment_type
        ).first()
        
        if existing_fee_breakdown:
            # Update existing record
            existing_fee_breakdown.paid = form.paid.data
            existing_fee_breakdown.due = calculated_due
            existing_fee_breakdown.receipt_no = form.receipt_no.data
            existing_fee_breakdown.fee_paid_date = form.fee_paid_date.data
            existing_fee_breakdown.updated_by = current_user.username
            
            db.session.commit()
            
            log_activity('updated', 'FeeBreakdown', 
                        f"{pen_num}-{year}-{fee_type}-{term}-{payment_type}", 
                        f"Updated fee payment of ₹{form.paid.data} for {student_name}, " +
                        f"Fee type: {fee_type}, Term: {term}")
            
            flash('Fee breakdown updated successfully!', 'success')
        else:
            # Create new record
            db.session.add(FeeBreakdown(
                pen_num=pen_num,
                year=year,
                fee_type=fee_type,
                term=term,
                payment_type=payment_type,
                paid=form.paid.data,
                due=calculated_due,
                receipt_no=form.receipt_no.data,
                fee_paid_date=form.fee_paid_date.data,
                created_by=current_user.username
            ))
            db.session.commit()
            
            log_activity('added', 'FeeBreakdown', 
                        f"{pen_num}-{year}-{fee_type}-{term}-{payment_type}", 
                        f"Received fee payment of ₹{form.paid.data} from {student_name}, " +
                        f"Fee type: {fee_type}, Term: {term}")
            
            flash('Fee breakdown added successfully!', 'success')
            
        return redirect(url_for('home'))
        
    return render_template('fee_breakdown_form.html', title='Fee Breakdown', form=form, fee_breakdown=fee_breakdown)

@app.route("/import_fee_breakdown_csv", methods=['GET', 'POST'])
@login_required
@admin_required
def import_fee_breakdown_csv():
    if request.method == 'POST':
        def process_fee_breakdown_rows(csv_reader):
            stats = {'imported': 0, 'updated': 0, 'failed': 0}
            
            # Map column headers that might include format specifications
            date_column_map = {}
            if csv_reader.fieldnames:
                for field in csv_reader.fieldnames:
                    # Check if this is a date field with format specification
                    if 'fee_paid_date' in field.lower():
                        date_column_map['fee_paid_date'] = field
            
            for row in csv_reader:
                try:
                    # Process data with safe type conversion
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
                    
                    # Get date values using the mapped column names
                    fee_paid_date_str = str(row.get(date_column_map.get('fee_paid_date', 'fee_paid_date'), "")).strip()
                    fee_paid_date = None
                    
                    # Parse the date with the format specified in the header
                    if fee_paid_date_str:
                        try:
                            # Try dd.mm.yyyy format first (common in your data)
                            fee_paid_date = datetime.strptime(fee_paid_date_str, '%d.%m.%Y').date()
                        except ValueError:
                            try:
                                # Try mm.dd.yyyy format
                                fee_paid_date = datetime.strptime(fee_paid_date_str, '%m.%d.%Y').date()
                            except ValueError:
                                try:
                                    # Try yyyy-mm-dd format
                                    fee_paid_date = datetime.strptime(fee_paid_date_str, '%Y-%m-%d').date()
                                except ValueError:
                                    try:
                                        # Try dd/mm/yyyy format
                                        fee_paid_date = datetime.strptime(fee_paid_date_str, '%d/%m/%Y').date()
                                    except ValueError:
                                        try:
                                            # Try mm/dd/yyyy format
                                            fee_paid_date = datetime.strptime(fee_paid_date_str, '%m/%d/%Y').date()
                                        except ValueError:
                                            raise ValueError(f"Invalid date format for fee_paid_date: {fee_paid_date_str}")
                    else:
                        # Use current date if none provided
                        fee_paid_date = datetime.now().date()

                    # Basic validation
                    if not pen_num or not year or not fee_type or not term:
                        raise ValueError("Missing required fee breakdown details")

                    # Check if student and fee record exist
                    student = Student.query.get(pen_num)
                    if not student:
                        raise ValueError(f"Student with PEN {pen_num} does not exist")
                        
                    fee_record = Fee.query.filter_by(pen_num=pen_num, year=year).first()
                    if not fee_record:
                        raise ValueError(f"Fee record for PEN {pen_num}, Year {year} does not exist")

                    # Check if record exists
                    existing_fee_breakdown = FeeBreakdown.query.filter_by(
                        pen_num=pen_num, year=year, fee_type=fee_type, term=term, payment_type=payment_type
                    ).first()

                    if existing_fee_breakdown:
                        # Update existing record
                        existing_fee_breakdown.paid = paid
                        existing_fee_breakdown.due = due
                        existing_fee_breakdown.receipt_no = receipt_no
                        existing_fee_breakdown.fee_paid_date = fee_paid_date
                        existing_fee_breakdown.updated_by = current_user.username
                        stats['updated'] += 1
                    else:
                        # Insert new record
                        db.session.add(FeeBreakdown(
                            pen_num=pen_num,
                            year=year,
                            fee_type=fee_type,
                            term=term,
                            payment_type=payment_type,
                            paid=paid,
                            due=due,
                            receipt_no=receipt_no,
                            fee_paid_date=fee_paid_date,
                            created_by=current_user.username
                        ))
                        stats['imported'] += 1

                    # Periodic flush
                    if (stats['imported'] + stats['updated']) % 100 == 0:
                        db.session.flush()

                except Exception as e:
                    db.session.rollback()
                    flash(f"Error in row {stats['imported'] + stats['updated'] + stats['failed'] + 1}: {str(e)}", "danger")
                    stats['failed'] += 1
                    
            # Final commit
            try:
                db.session.commit()
                log_activity('imported', 'FeeBreakdown', 'BULK', 
                            f"Imported {stats['imported']} fee payments, updated {stats['updated']} via CSV")
                flash(f"{stats['imported']} records imported, {stats['updated']} records updated, {stats['failed']} records failed.", 'success')
            except Exception as e:
                db.session.rollback()
                flash(f"Database error during commit: {str(e)}", "danger")
                
            return redirect(url_for('home'))
            
        return process_csv_import(request.files, 'fee_breakdown_csv', process_fee_breakdown_rows, 'home')
        
    return render_template('import_fee_breakdown_csv.html', title='Import Fee Breakdown CSV')

# --- Data Viewing and Export ---
@app.route("/view_table", methods=["GET", "POST"])
@login_required
def view_table():
    form = TableSelectForm()
    table_name = request.args.get("table_name", None)
    
    # Initialize data and dates
    data = None
    start_date = None
    end_date = None
    pen_num = None

    # Retrieve session values if they exist
    start_date_str = session.get('start_date')
    end_date_str = session.get('end_date')
    pen_num_str = session.get('pen_num')

    if start_date_str:
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
    if end_date_str:
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
    
    if request.method == "POST":
        table_name = request.form.get("table_select")
        start_date_str = request.form.get("start_date")
        end_date_str = request.form.get("end_date")
        pen_num_str = request.form.get("pen_num")
        
        # Process start and end dates
        if start_date_str:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
            session['start_date'] = start_date_str
        else:
            session.pop('start_date', None)
            
        if end_date_str:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
            session['end_date'] = end_date_str
        else:
            session.pop('end_date', None)
        
        # Process pen_num (Clear for transport table)
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
        
        # Get model class based on table name
        models = {
            "student": Student,
            "classdetails": ClassDetails,
            "fee": Fee,
            "feebreakdown": FeeBreakdown,
            "transport": Transport
        }
        
        model = models.get(table_name)
        if model:
            query = model.query
            
            # Apply date filters
            if hasattr(model, 'created_at'):
                if start_date:
                    query = query.filter(model.created_at >= start_date)
                if end_date:
                    query = query.filter(model.created_at <= end_date + timedelta(days=1))
            
            # Apply PEN filter for applicable tables (not transport)
            if pen_num and hasattr(model, 'pen_num'):
                query = query.filter(model.pen_num == pen_num)
            
            data = query.all()
            
            log_activity('viewed', table_name, 'QUERY', 
                       f"Viewed {table_name} data with filters: " + 
                       (f"date range {start_date} to {end_date}" if start_date and end_date else "no date filter") + 
                       (f", PEN: {pen_num}" if pen_num else ""))
        else:
            flash("Invalid table selected", "danger")
            
    return render_template("view_table.html", data=data, table_name=table_name, form=form,
                           start_date=start_date, end_date=end_date)


@app.route("/export_csv/<table_name>", methods=["GET"])
@login_required
def export_csv(table_name):
    # Get all filters from request args, falling back to session
    start_date_str = request.args.get('start_date') or session.get('start_date')
    end_date_str = request.args.get('end_date') or session.get('end_date')
    pen_num_str = request.args.get('pen_num') or session.get('pen_num')

    start_date = datetime.strptime(start_date_str, '%Y-%m-%d') if start_date_str else None
    end_date = datetime.strptime(end_date_str, '%Y-%m-%d') if end_date_str else None
    pen_num = int(pen_num_str) if pen_num_str else None
    
    # Define table configurations
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
    
    config = table_configs.get(table_name)
    if not config:
        return "Invalid table name", 400
    
    # Query data with all filters
    query = config["model"].query
    query = apply_date_filter(query, config["model"], start_date, end_date)
    
    # Apply PEN filter if applicable
    model = config["model"]
    if pen_num and hasattr(model, 'pen_num'):
        query = query.filter(model.pen_num == pen_num)
    
    data = query.all()
    
    log_activity('exported', table_name, 'CSV', 
               f"Exported {table_name} data to CSV with filters: " + 
               (f"date range {start_date} to {end_date}" if start_date and end_date else "no date filter") + 
               (f", PEN: {pen_num}" if pen_num else ""))
    
    # Generate CSV response
    return prepare_csv_response(data, config["fields"], table_name)