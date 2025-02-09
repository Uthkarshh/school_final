from flask import render_template, flash, redirect, url_for, request, abort
from school import app, db, bcrypt
from school.forms import RegistrationForm, LoginForm, UpdateAccountForm, StudentForm, ClassDetailsForm, FeeBreakdownForm, FeeForm, TransportForm
from school.models import User, Student, ClassDetails, Fee, FeeBreakdown, Transport
from flask_login import login_user, current_user, logout_user, login_required
import secrets
from sqlalchemy.exc import IntegrityError
import csv
from io import TextIOWrapper
from datetime import datetime
from PIL import Image

@app.route("/")
@app.route("/home")
def home():
    pages = [
        {"name": "Register", "relative_path": url_for('register')},
        {"name": "Login", "relative_path": url_for('login')},
        {"name": "Student Form", "relative_path": url_for('student_form')},
        {"name": "Transport Form", "relative_path": url_for('transport_form')},
        {"name": "Class Details", "relative_path": url_for('class_details_form')},
        {"name": "Fee Form", "relative_path": url_for('fee_form')},
        {"name": "Fee Breakdown", "relative_path": url_for('fee_breakdown_form')}
    ]

    return render_template("home.html", pages=pages)

@app.route("/about")
@login_required
def about():
    return render_template("about.html", title= "About me")

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        # Check if any users exist in the database
        first_user = User.query.count() == 0

        if first_user:
            # Automatically approve and set user role to 'Admin' for the first user
            user = User(username=form.username.data,
                        email=form.email.data,
                        user_role='Admin', # Set user_role to Admin
                        password=hashed_password,
                        is_approved=True) # Auto-approve the first user
            approval_message = 'Your admin account has been automatically approved. You can now log in.' # Custom flash message
            role_set_message = 'Admin role set automatically.'
        else:
            # Normal registration for subsequent users (pending admin approval)
            user = User(username=form.username.data,
                        email=form.email.data,
                        user_role=form.user_role.data,
                        password=hashed_password)
            approval_message = 'Your registration is pending admin approval. You will be notified once your account is approved.'
            role_set_message = 'User role will be reviewed by admin.'


        db.session.add(user)
        db.session.commit()

        flash(approval_message, 'info')
        flash(role_set_message, 'info') # Optional flash message about role
        return redirect(url_for('login'))

    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods = ["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            if user.is_approved: # Check is_approved status
                login_user(user, remember=form.remember.data)
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('home'))
            else:
                flash('Your account is pending admin approval. Please wait for approval.', 'warning')
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title = 'Login', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/account", methods = ["GET", "POST"])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', category='success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email

@app.route("/admin/users")
@login_required
def admin_users():
    if current_user.user_role != 'Admin':
        abort(403) # Only admins can access this

    users = User.query.all() # Get all users now
    return render_template('admin_users.html', users=users, title='Admin - User Management')

@app.route("/admin/users/toggle_approve/<int:user_id>")
@login_required
def toggle_user_approval(user_id):
    if current_user.user_role != 'Admin':
        abort(403)

    user = User.query.get_or_404(user_id)
    user.is_approved = not user.is_approved # Toggle the approval status
    db.session.commit()

    if user.is_approved:
        flash(f'User {user.username} has been approved.', 'success')
    else:
        flash(f'Access revoked for user {user.username}.', 'warning') # Updated flash message for revoke

    return redirect(url_for('admin_users')) # Redirect back to admin users page

@app.route("/admin/users/reject/<int:user_id>")
@login_required
def reject_user(user_id):
    if current_user.user_role != 'Admin':
        abort(403)

    user = User.query.get_or_404(user_id)
    db.session.delete(user) # Or you could set is_rejected=True instead of deleting
    db.session.commit()
    flash(f'User {user.username} has been rejected and deleted.', 'danger')
    return redirect(url_for('admin_users'))

@app.route("/student_form", methods=['GET', 'POST'])
@login_required
def student_form():
    if current_user.user_role != 'Admin':
        abort(403)
    form = StudentForm()
    if form.validate_on_submit():
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
        flash('Student record added successfully!', 'success')
        return redirect(url_for('student_form'))
    return render_template('student_form.html', title='Student Form', form=form)

@app.route("/import_student_csv", methods=['GET', 'POST'])
@login_required
def import_student_csv():
    if current_user.user_role != 'Admin':
        abort(403)

    if request.method == 'POST':
        if 'student_csv' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)

        file = request.files['student_csv']

        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)

        if file and file.filename.endswith('.csv'):
            try:
                csv_file = TextIOWrapper(file.stream, encoding='utf-8')
                csv_reader = csv.DictReader(csv_file)

                students_imported = 0
                students_updated = 0
                students_failed = 0

                for row in csv_reader:
                    try:
                        # Convert values safely, handle missing values using .get and strip
                        pen_num = int(row.get("pen_num", "0").strip() or 0)
                        admission_number = int(row.get("admission_number", "0").strip() or 0)
                        aadhar_number = int(row.get("aadhar_number", "0").strip() or 0)
                        student_name = row.get("student_name", "").strip()
                        father_name = row.get("father_name", "").strip()
                        mother_name = row.get("mother_name", "").strip()
                        gender = row.get("gender", "").strip()
                        date_of_birth_str = row.get("date_of_birth", "").strip()
                        date_of_joining_str = row.get("date_of_joining", "").strip()
                        contact_number = row.get("contact_number", "").strip()
                        village = row.get("village", "").strip()

                        # Convert date strings to date objects, handle potential empty date strings
                        date_of_birth = datetime.strptime(date_of_birth_str, '%Y-%m-%d').date() if date_of_birth_str else None
                        date_of_joining = datetime.strptime(date_of_joining_str, '%Y-%m-%d').date() if date_of_joining_str else None

                        # Check if record exists based on pen_num
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
                            existing_student.updated_by = current_user.username # Track who updated
                            students_updated += 1
                        else:
                            # Insert new record
                            student = Student(
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
                                created_by=current_user.username # Track who created
                            )
                            db.session.add(student)
                            students_imported += 1

                        db.session.flush()  # Commit each row

                    except ValueError as ve:
                        print(f"Data conversion error in row {row}: {ve}")
                        flash(f"Data format error in row {row}: {ve}", "danger")
                        students_failed += 1
                    except IntegrityError as ie:
                        print(f"Integrity error in row {row}: {ie}")
                        db.session.rollback() # Rollback individual row
                        flash(f"Database constraint error for row {row}: {ie}", "danger")
                        students_failed += 1
                    except Exception as e:
                        print(f"Unexpected error in row {row}: {e}")
                        db.session.rollback()
                        flash(f"Unexpected error in row {row}: {e}", "danger")
                        students_failed += 1

                db.session.commit() # Final commit after all rows
                flash(f'{students_imported} records imported, {students_updated} records updated, {students_failed} records failed.', 'success')

            except Exception as e:
                flash(f'Error processing CSV file: {str(e)}', 'danger')

            return redirect(url_for('home')) # Redirect to home or student list page

    return render_template('import_student_csv.html', title='Import Student CSV')


@app.route("/transport_form", methods=['GET', 'POST'])
@login_required
def transport_form():
    if current_user.user_role != 'Admin':
        abort(403)
    form = TransportForm()
    if form.validate_on_submit():
        transport = Transport(
            pick_up_point=form.pick_up_point.data,
            route_number=form.route_number.data,
            created_by=current_user.username
        )
        db.session.add(transport)
        db.session.commit()
        flash('Transport record added successfully!', 'success')
        return redirect(url_for('home'))
    return render_template('transport_form.html', title='Transport Form', form=form)

@app.route("/import_transport_csv", methods=['GET', 'POST'])
@login_required
def import_transport_csv():
    if current_user.user_role != 'Admin':
        abort(403)

    if request.method == 'POST':
        if 'transport_csv' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)

        file = request.files['transport_csv']
        
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)

        if file and file.filename.endswith('.csv'):
            try:
                # Decode the file properly for universal support
                csv_file = TextIOWrapper(file.stream, encoding='utf-8')
                csv_reader = csv.DictReader(csv_file)  # Read CSV by column names
                
                transports_imported = 0
                transports_failed = 0

                for row in csv_reader:
                    try:
                        pick_up_point = row.get("pick_up_point", "").strip()
                        route_number = row.get("route_number", "").strip()

                        # Validate required fields
                        if not pick_up_point or not route_number:
                            raise ValueError("Missing required transport details")

                        transport = Transport(
                            pick_up_point=pick_up_point,
                            route_number=route_number,
                            created_by=current_user.username
                        )

                        db.session.add(transport)
                        transports_imported += 1
                    
                    except ValueError as ve:
                        print(f"Data format issue in row {row}: {ve}")
                        transports_failed += 1
                        db.session.rollback()  # Rollback only on failed row

                    except Exception as e:
                        print(f"Unexpected error in row {row}: {e}")
                        transports_failed += 1
                        db.session.rollback()

                db.session.commit()  # Commit all valid records at once
                flash(f'{transports_imported} transport records imported successfully! {transports_failed} records failed.', 'success')

            except Exception as e:
                flash(f'Error processing CSV file: {str(e)}', 'danger')

            return redirect(url_for('home'))  # Redirect to a transport list page if needed

    return render_template('import_transport_csv.html', title='Import Transport CSV')



@app.route("/class_details_form", methods=['GET', 'POST'])
@login_required
def class_details_form():
    if current_user.user_role != 'Admin':
        abort(403)
    form = ClassDetailsForm()
    if form.validate_on_submit():
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
        flash('Class details added successfully!', 'success')
        return redirect(url_for('home'))
    return render_template('class_details_form.html', title='Class Details', form=form)


@app.route("/import_class_details_csv", methods=['GET', 'POST'])
@login_required
def import_class_details_csv():
    if current_user.user_role != 'Admin':
        abort(403)

    if request.method == 'POST':
        if 'class_details_csv' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)

        file = request.files['class_details_csv']

        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)

        if file and file.filename.endswith('.csv'):
            try:
                csv_file = TextIOWrapper(file.stream, encoding='utf-8')
                csv_reader = csv.DictReader(csv_file)

                class_details_imported = 0
                class_details_updated = 0
                class_details_failed = 0

                for row in csv_reader:
                    try:
                        # Convert values safely
                        pen_num = int(row.get("pen_num", "0").strip() or 0)
                        year = int(row.get("year", "0").strip() or 0)
                        current_class = int(row.get("current_class", "0").strip() or 0)
                        section = row.get("section", "").strip()
                        roll_number = int(row.get("roll_number", "0").strip() or 0)
                        photo_id = int(row.get("photo_id", "0").strip() or 0)
                        language = row.get("language", "").strip()
                        vocational = row.get("vocational", "").strip()
                        currently_enrolled = row.get("currently_enrolled", "").strip().lower() in ["true", "1", "yes"]

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
                            existing_record.updated_by = current_user.username  # Track who updated the record
                            class_details_updated += 1
                        else:
                            # Insert new record
                            class_details = ClassDetails(
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
                            )
                            db.session.add(class_details)
                            class_details_imported += 1

                        db.session.flush()  # Commit only this row

                    except ValueError as ve:
                        print(f"Data conversion error in row {row}: {ve}")
                        flash(f"Data format error in row {row}: {ve}", "danger")
                        class_details_failed += 1
                    except IntegrityError as ie:
                        print(f"Integrity error in row {row}: {ie}")
                        db.session.rollback()  # Rollback only current row
                        flash(f"Database constraint error for row {row}: {ie}", "danger")
                        class_details_failed += 1
                    except Exception as e:
                        print(f"Unexpected error in row {row}: {e}")
                        db.session.rollback()
                        flash(f"Unexpected error in row {row}: {e}", "danger")
                        class_details_failed += 1

                db.session.commit()  # Final commit after all records
                flash(f'{class_details_imported} records imported, {class_details_updated} records updated, {class_details_failed} records failed.', 'success')

            except Exception as e:
                flash(f'Error processing CSV file: {str(e)}', 'danger')

            return redirect(url_for('home'))

    return render_template('import_class_details_csv.html', title='Import Class Details CSV')




@app.route("/fee_form", methods=['GET', 'POST'])
@login_required
def fee_form():
    if current_user.user_role != 'Admin':
        abort(403)
    form = FeeForm()
    if form.validate_on_submit():
        fee = Fee(
            pen_num=form.pen_num.data,
            year=form.year.data,
            school_fee=form.school_fee.data,
            concession_reason=form.concession_reason.data,
            transport_used=form.transport_used.data,
            application_fee=form.application_fee.data,
            transport_fee=form.transport_fee.data,
            transport_fee_concession=form.transport_fee_concession.data,
            transport_id=form.transport_id.data,
            created_by=current_user.username
        )
        db.session.add(fee)
        db.session.commit()
        flash('Fee record added successfully!', 'success')
        return redirect(url_for('home'))
    return render_template('fee_form.html', title='Fee Form', form=form)

@app.route("/import_fee_csv", methods=['GET', 'POST'])
@login_required
def import_fee_csv():
    if current_user.user_role != 'Admin':
        abort(403)

    if request.method == 'POST':
        if 'fee_csv' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)

        file = request.files['fee_csv']

        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)

        if file and file.filename.endswith('.csv'):
            try:
                csv_file = TextIOWrapper(file.stream, encoding='utf-8')
                csv_reader = csv.DictReader(csv_file)

                fees_imported = 0
                fees_updated = 0
                fees_failed = 0

                for row in csv_reader:
                    try:
                        # Convert values safely, handle missing values using .get and strip
                        pen_num = int(row.get("pen_num", "0").strip() or 0)
                        year = int(row.get("year", "0").strip() or 0)
                        school_fee = float(row.get("school_fee", "0.0").strip() or 0.0)
                        concession_reason = row.get("concession_reason", "").strip()
                        transport_used_str = row.get("transport_used", "").strip().lower()
                        application_fee = float(row.get("application_fee", "0.0").strip() or 0.0)
                        transport_fee = float(row.get("transport_fee", "0.0").strip() or 0.0)
                        transport_fee_concession = float(row.get("transport_fee_concession", "0.0").strip() or 0.0)
                        transport_id_str = row.get("transport_id", "").strip()

                        # Convert boolean and integer values
                        transport_used = transport_used_str in ["true", "1", "yes"]
                        transport_id = int(transport_id_str) if transport_id_str else None

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
                            existing_fee.updated_by = current_user.username # Track who updated
                            fees_updated += 1
                        else:
                            # Insert new record
                            fee = Fee(
                                pen_num=pen_num,
                                year=year,
                                school_fee=school_fee,
                                concession_reason=concession_reason,
                                transport_used=transport_used,
                                application_fee=application_fee,
                                transport_fee=transport_fee,
                                transport_fee_concession=transport_fee_concession,
                                transport_id=transport_id,
                                created_by=current_user.username # Track who created
                            )
                            db.session.add(fee)
                            fees_imported += 1

                        db.session.flush() # Commit each row

                    except ValueError as ve:
                        print(f"Data conversion error in row {row}: {ve}")
                        flash(f"Data format error in row {row}: {ve}", "danger")
                        fees_failed += 1
                    except IntegrityError as ie:
                        print(f"Integrity error in row {row}: {ie}")
                        db.session.rollback() # Rollback individual row
                        flash(f"Database constraint error for row {row}: {ie}", "danger")
                        fees_failed += 1
                    except Exception as e:
                        print(f"Unexpected error in row {row}: {e}")
                        db.session.rollback()
                        flash(f"Unexpected error in row {row}: {e}", "danger")
                        fees_failed += 1

                db.session.commit() # Final commit after all rows
                flash(f'{fees_imported} records imported, {fees_updated} records updated, {fees_failed} records failed.', 'success')

            except Exception as e:
                flash(f'Error processing CSV file: {str(e)}', 'danger')

            return redirect(url_for('home'))

    return render_template('import_fee_csv.html', title='Import Fee CSV')



@app.route("/fee_breakdown_form", methods=['GET', 'POST'])
@login_required
def fee_breakdown_form():
    if current_user.user_role != 'Admin':
        abort(403)
    form = FeeBreakdownForm()
    if form.validate_on_submit():
        fee_breakdown = FeeBreakdown(
            pen_num=form.pen_num.data,
            year=form.year.data,
            fee_type=form.fee_type.data,
            term=form.term.data,
            paid=form.paid.data,
            due=form.due.data,
            receipt_no=form.receipt_no.data,
            fee_paid_date=form.fee_paid_date.data,
            created_by=current_user.username
        )
        db.session.add(fee_breakdown)
        db.session.commit()
        flash('Fee breakdown added successfully!', 'success')
        return redirect(url_for('home'))
    return render_template('fee_breakdown_form.html', title='Fee Breakdown', form=form)

@app.route("/import_fee_breakdown_csv", methods=['GET', 'POST'])
@login_required
def import_fee_breakdown_csv():
    if current_user.user_role != 'Admin':
        abort(403)

    if request.method == 'POST':
        if 'fee_breakdown_csv' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)

        file = request.files['fee_breakdown_csv']

        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)

        if file and file.filename.endswith('.csv'):
            try:
                csv_file = TextIOWrapper(file.stream, encoding='utf-8')
                csv_reader = csv.DictReader(csv_file)

                fee_breakdowns_imported = 0
                fee_breakdowns_updated = 0
                fee_breakdowns_failed = 0

                for row in csv_reader:
                    try:
                        # Convert values safely, handle missing values using .get and strip
                        pen_num = int(row.get("pen_num", "0").strip() or 0)
                        year = int(row.get("year", "0").strip() or 0)
                        fee_type = row.get("fee_type", "").strip()
                        term = row.get("term", "").strip()
                        paid = float(row.get("paid", "0.0").strip() or 0.0)
                        due = float(row.get("due", "0.0").strip() or 0.0)
                        receipt_no_str = row.get("receipt_no", "").strip()
                        fee_paid_date_str = row.get("fee_paid_date", "").strip()

                        # Convert receipt_no to integer, handle potential empty or non-integer values
                        receipt_no = int(receipt_no_str) if receipt_no_str else None
                        # Convert date strings to date objects, handle potential empty date strings
                        fee_paid_date = datetime.strptime(fee_paid_date_str, '%Y-%m-%d').date() if fee_paid_date_str else None

                        # Check if record exists
                        existing_fee_breakdown = FeeBreakdown.query.filter_by(pen_num=pen_num, year=year, fee_type=fee_type, term=term).first()

                        if existing_fee_breakdown:
                            # Update existing record
                            existing_fee_breakdown.paid = paid
                            existing_fee_breakdown.due = due
                            existing_fee_breakdown.receipt_no = receipt_no
                            existing_fee_breakdown.fee_paid_date = fee_paid_date
                            existing_fee_breakdown.updated_by = current_user.username # Track who updated
                            fee_breakdowns_updated += 1
                        else:
                            # Insert new record
                            fee_breakdown = FeeBreakdown(
                                pen_num=pen_num,
                                year=year,
                                fee_type=fee_type,
                                term=term,
                                paid=paid,
                                due=due,
                                receipt_no=receipt_no,
                                fee_paid_date=fee_paid_date,
                                created_by=current_user.username # Track who created
                            )
                            db.session.add(fee_breakdown)
                            fee_breakdowns_imported += 1

                        db.session.flush() # Commit each row

                    except ValueError as ve:
                        print(f"Data conversion error in row {row}: {ve}")
                        flash(f"Data format error in row {row}: {ve}", "danger")
                        fee_breakdowns_failed += 1
                    except IntegrityError as ie:
                        print(f"Integrity error in row {row}: {ie}")
                        db.session.rollback() # Rollback individual row
                        flash(f"Database constraint error for row {row}: {ie}", "danger")
                        fee_breakdowns_failed += 1
                    except Exception as e:
                        print(f"Unexpected error in row {row}: {e}")
                        db.session.rollback()
                        flash(f"Unexpected error in row {row}: {e}", "danger")
                        fee_breakdowns_failed += 1

                db.session.commit() # Final commit after all rows
                flash(f'{fee_breakdowns_imported} records imported, {fee_breakdowns_updated} records updated, {fee_breakdowns_failed} records failed.', 'success')

            except Exception as e:
                flash(f'Error processing CSV file: {str(e)}', 'danger')

            return redirect(url_for('home'))

    return render_template('import_fee_breakdown_csv.html', title='Import Fee Breakdown CSV')
