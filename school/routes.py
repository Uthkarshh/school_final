from flask import render_template, flash, redirect, url_for, request, abort
from school import app, db, bcrypt
from school.forms import RegistrationForm, LoginForm, UpdateAccountForm, StudentForm, ClassDetailsForm, FeeBreakdownForm, FeeForm, TransportForm
from school.models import User, Student, ClassDetails, Fee, FeeBreakdown, Transport
from flask_login import login_user, current_user, logout_user, login_required
import secrets
import os
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
        return redirect(url_for('home'))
    return render_template('student_form.html', title='Student Form', form=form)


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