from school import db, login_manager
from datetime import datetime, timezone
from flask_login import UserMixin, login_user, current_user
from sqlalchemy import event

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    user_role = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_approved = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

def set_user_metadata(target):
    """Sets created_by and updated_by automatically."""
    username = getattr(current_user, "username", "System")
    if not target.created_by:
        target.created_by = username
    target.updated_by = username

class Student(db.Model):
    __tablename__ = 'student'

    pen_num = db.Column(db.BigInteger, primary_key=True, nullable=False)
    admission_number = db.Column(db.BigInteger, unique=True, nullable=False)
    aadhar_number = db.Column(db.BigInteger, unique=True, nullable=False)
    student_name = db.Column(db.String(60), nullable=False)
    father_name = db.Column(db.String(60), nullable=False)
    mother_name = db.Column(db.String(60), nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False)
    date_of_joining = db.Column(db.Date, nullable=False)
    contact_number = db.Column(db.String(20), nullable=False)
    village = db.Column(db.String(50), nullable=False)

    # Track user actions
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    created_by = db.Column(db.String(20), nullable=False)
    updated_by = db.Column(db.String(20), nullable=True)

    def __repr__(self):
        return f"Student('{self.pen_num}', '{self.student_name}', '{self.father_name}')"

@event.listens_for(Student, 'before_insert')
@event.listens_for(Student, 'before_update')
def before_student_save(mapper, connection, target):
    set_user_metadata(target)

class Transport(db.Model):
    __tablename__ = 'transport'

    transport_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    pick_up_point = db.Column(db.String(50), nullable=False)
    route_number = db.Column(db.Integer, nullable=False)

    # Track user actions
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    created_by = db.Column(db.String(20), nullable=False)
    updated_by = db.Column(db.String(20), nullable=True)

    def __repr__(self):
        return f"Transport('{self.transport_id}', '{self.pick_up_point}', '{self.route_number}')"

@event.listens_for(Transport, 'before_insert')
@event.listens_for(Transport, 'before_update')
def before_transport_save(mapper, connection, target):
    set_user_metadata(target)

class ClassDetails(db.Model):
    __tablename__ = 'class_details'

    pen_num = db.Column(db.BigInteger, db.ForeignKey('student.pen_num'), primary_key=True, nullable=False)
    year = db.Column(db.Integer, primary_key=True, nullable=False)
    current_class = db.Column(db.Integer, nullable=False)
    section = db.Column(db.String(2), nullable=False)
    roll_number = db.Column(db.Integer, nullable=False)
    photo_id = db.Column(db.Integer, unique=True, nullable=False)
    language = db.Column(db.String(50), nullable=False)
    vocational = db.Column(db.String(50), nullable=False)
    currently_enrolled = db.Column(db.Boolean, default=True)

    student = db.relationship('Student', backref=db.backref('class_details', lazy=True))

    # Track user actions
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    created_by = db.Column(db.String(20), nullable=False)
    updated_by = db.Column(db.String(20), nullable=True)

    def __repr__(self):
        return f"ClassDetails('{self.pen_num}', '{self.year}', '{self.current_class}', '{self.section}')"

@event.listens_for(ClassDetails, 'before_insert')
@event.listens_for(ClassDetails, 'before_update')
def before_classdetails_save(mapper, connection, target):
    set_user_metadata(target)

class Fee(db.Model):
    __tablename__ = 'fee'

    pen_num = db.Column(db.BigInteger, db.ForeignKey('student.pen_num'), primary_key=True, nullable=False)
    year = db.Column(db.Integer, primary_key=True, nullable=False)
    school_fee = db.Column(db.Integer, nullable=False)
    concession_reason = db.Column(db.String(50), nullable=True)
    school_fee_concession = db.Column(db.Integer, nullable=False, default=0)
    transport_used = db.Column(db.Boolean, nullable=False, default=False)
    application_fee = db.Column(db.Integer, nullable=False)
    transport_fee = db.Column(db.Integer, nullable=True)
    transport_fee_concession = db.Column(db.Integer, nullable=True)
    transport_id = db.Column(db.Integer, db.ForeignKey('transport.transport_id'), nullable=True)

    student = db.relationship('Student', backref=db.backref('fee_records', lazy=True))
    transport = db.relationship('Transport', backref=db.backref('fee_records', lazy=True))

    @staticmethod
    def calculate_school_fee_concession(reason, school_fee):
        concession_map = {
            'Staff': 0.5,
            'Sibbling': 0.1,
            'OTP': 0.1,
            'General': 0.1,
            'TF': 0.05,
            'FP': 0.2,
            'EC': 0.15,
            'SC': 0.25
        }
        return school_fee * concession_map.get(reason, 0)
    
    # Track user actions
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    created_by = db.Column(db.String(20), nullable=False)
    updated_by = db.Column(db.String(20), nullable=True)
    
    def __repr__(self):  #Improved for better readability
        return (f"Fee(pen_num={self.pen_num}, year={self.year}, school_fee={self.school_fee}, "
                f"concession_reason='{self.concession_reason}', school_fee_concession={self.school_fee_concession}, "
                f"transport_used={self.transport_used}, application_fee={self.application_fee}, "
                f"transport_fee={self.transport_fee}, transport_fee_concession={self.transport_fee_concession}, "
                f"transport_id={self.transport_id})")
    
@event.listens_for(Fee, 'before_insert')
@event.listens_for(Fee, 'before_update')
def before_fee_save(mapper, connection, target):
    target.school_fee_concession = target.calculate_school_fee_concession(target.concession_reason, target.school_fee)
    set_user_metadata(target)


class FeeBreakdown(db.Model):
    __tablename__ = 'fee_breakdown'

    pen_num = db.Column(db.BigInteger, db.ForeignKey('student.pen_num'), primary_key=True, nullable=False)
    year = db.Column(db.Integer, primary_key=True, nullable=False)
    fee_type = db.Column(db.String(50), primary_key=True, nullable=False)
    term = db.Column(db.String(5), primary_key=True, nullable=False)
    payment_type = db.Column(db.String(15), primary_key=True, nullable=False)
    paid = db.Column(db.Numeric(10, 2), nullable=False, default=0)
    due = db.Column(db.Numeric(10, 2), nullable=False, default=0)
    receipt_no = db.Column(db.Integer, nullable=True)  
    fee_paid_date = db.Column(db.Date, nullable=True) 

    student = db.relationship('Student', backref=db.backref('fee_breakdown', lazy=True))

    # Track user actions
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    created_by = db.Column(db.String(20), nullable=False)
    updated_by = db.Column(db.String(20), nullable=True)

    def __repr__(self):
        return f"FeeBreakdown(pen_num={self.pen_num}, year={self.year}, fee_type='{self.fee_type}', term='{self.term}', paid={self.paid}, due={self.due})"

@event.listens_for(FeeBreakdown, 'before_insert')
@event.listens_for(FeeBreakdown, 'before_update')
def before_feebreakdown_save(mapper, connection, target):
    set_user_metadata(target)


class ActivityLog(db.Model):
    __tablename__ = 'activity_log'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action_type = db.Column(db.String(50), nullable=False)  # e.g., "added", "updated", "deleted"
    entity_type = db.Column(db.String(50), nullable=False)  # e.g., "Student", "Fee", "Transport"
    entity_id = db.Column(db.String(50), nullable=False)    # Primary key of the affected entity
    description = db.Column(db.String(255), nullable=False) # Human-readable description
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('activities', lazy=True))
    
    def __repr__(self):
        return f"Activity('{self.action_type}', '{self.entity_type}', '{self.entity_id}')"
