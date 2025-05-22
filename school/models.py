"""Database models for the school fee management application."""

import logging
import re
from datetime import date, datetime
from typing import Any, Dict, List, Optional, Union, cast

from flask_login import UserMixin, current_user
from sqlalchemy import Index, event, func
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import validates

from school import db, login_manager

# Configure logging
logger = logging.getLogger(__name__)


@login_manager.user_loader
def load_user(user_id: str) -> Optional["User"]:
    """Load user by ID for Flask-Login.

    Args:
        user_id: The user ID to load

    Returns:
        User object if found, None otherwise
    """
    try:
        return User.query.get(int(user_id))
    except (ValueError, TypeError) as e:
        logger.error(f"Invalid user_id format: {user_id}, error: {e}")
        return None


class User(db.Model, UserMixin):
    """User model for authentication and authorization."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    user_role = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_approved = db.Column(db.Boolean, default=False)
    last_login = db.Column(db.DateTime, nullable=True)
    failed_login_attempts = db.Column(db.Integer, default=0)
    account_locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Indexes for performance
    __table_args__ = (
        Index("ix_users_username", "username"),
        Index("ix_users_email", "email"),
        Index("ix_users_user_role", "user_role"),
    )

    def __repr__(self) -> str:
        """String representation of the User model.

        Returns:
            String representation with username and email
        """
        return f"User('{self.username}', '{self.email}')"

    @property
    def is_admin(self) -> bool:
        """Check if user has admin role.

        Returns:
            True if user has admin role, False otherwise
        """
        return self.user_role.lower() == "admin"

    @property
    def is_locked(self) -> bool:
        """Check if user account is locked.

        Returns:
            True if account is locked, False otherwise
        """
        if not self.account_locked_until:
            return False
        return self.account_locked_until > datetime.now()

    @validates("username")
    def validate_username(self, key: str, username: str) -> str:
        """Validate username format.

        Args:
            key: Field name
            username: Username to validate

        Returns:
            Validated username

        Raises:
            ValueError: If username format is invalid
        """
        if not username or len(username) < 3:
            raise ValueError("Username must be at least 3 characters long")
        if not re.match(r"^[a-zA-Z0-9_]+$", username):
            raise ValueError("Username can only contain letters, numbers, and underscores")
        return username

    @validates("email")
    def validate_email(self, key: str, email: str) -> str:
        """Validate email format.

        Args:
            key: Field name
            email: Email to validate

        Returns:
            Validated email

        Raises:
            ValueError: If email format is invalid
        """
        if not email:
            raise ValueError("Email cannot be empty")
        if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
            raise ValueError("Invalid email format")
        return email

    @validates("user_role")
    def validate_user_role(self, key: str, role: str) -> str:
        """Validate user role.

        Args:
            key: Field name
            role: Role to validate

        Returns:
            Validated role

        Raises:
            ValueError: If role is invalid
        """
        valid_roles = ["admin", "teacher", "staff", "accountant"]
        if not role or role.lower() not in valid_roles:
            raise ValueError(f"User role must be one of: {', '.join(valid_roles)}")
        return role


def set_user_metadata(target: Any) -> None:
    """Sets created_by and updated_by automatically.

    Args:
        target: The model instance being updated
    """
    try:
        username = getattr(current_user, "username", "System")
        if hasattr(target, "created_by") and not target.created_by:
            target.created_by = username
        if hasattr(target, "updated_by"):
            target.updated_by = username
    except Exception as e:
        logger.error(f"Error setting user metadata: {e}")
        # Don't raise - this is non-critical functionality


def parse_date_from_string(date_val: Any, column_name: Optional[str] = None) -> Optional[date]:
    """Parse date string based on format hints in column name.

    Falls back to standard formats if no format is specified.
    Returns date object unchanged if already a date object.

    Args:
        date_val: The date value to parse
        column_name: Optional column name for format hints

    Returns:
        Parsed date object or None if date_val is empty

    Raises:
        ValueError: If the date cannot be parsed
    """
    if not date_val:
        return None

    # If already a date object, return it as is
    if isinstance(date_val, (datetime, date)):
        return date_val.date() if isinstance(date_val, datetime) else date_val

    # Process string values
    if not isinstance(date_val, str):
        date_val = str(date_val)

    date_str = date_val.strip()
    if not date_str:
        return None

    # Extract format from column name if possible
    format_pattern = None
    if column_name:
        # Extract the base column name and the format part
        match = re.search(r"(.*?)\s*\((.*?)\)", column_name)
        if match:
            format_hint = match.group(2).lower()

            # Convert format hint to datetime format string
            format_mapping = {
                "dd.mm.yyyy": "%d.%m.%Y",
                "mm.dd.yyyy": "%m.%d.%Y",
                "yyyy.mm.dd": "%Y.%m.%d",
                "dd/mm/yyyy": "%d/%m/%Y",
                "mm/dd/yyyy": "%m/%d/%Y",
                "yyyy/mm/dd": "%Y/%m/%d",
                "dd-mm-yyyy": "%d-%m-%Y",
                "mm-dd-yyyy": "%m-%d-%Y",
                "yyyy-mm-dd": "%Y-%m-%d",
            }

            for hint, pattern in format_mapping.items():
                if hint in format_hint:
                    format_pattern = pattern
                    break

    # Try to parse the date with the detected format or fall back to common formats
    if format_pattern:
        try:
            return datetime.strptime(date_str, format_pattern).date()
        except ValueError:
            pass

    # Try common formats if format-specific parsing fails
    formats = [
        "%Y-%m-%d",
        "%d-%m-%Y",
        "%m-%d-%Y",
        "%Y/%m/%d",
        "%d/%m/%Y",
        "%m/%d/%Y",
        "%Y.%m.%d",
        "%d.%m.%Y",
        "%m.%d.%Y",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt).date()
        except ValueError:
            continue

    # For the specific case of the student import, provide a default
    if column_name and "date_of_birth" in column_name:
        logger.warning(f"Using default date of birth for unparseable value: {date_str}")
        return datetime(2000, 1, 1).date()
    elif column_name and "date_of_joining" in column_name:
        logger.warning(f"Using current date for unparseable joining date: {date_str}")
        return datetime.now().date()

    raise ValueError(f"Unable to parse date: {date_str}")


class Student(db.Model):
    """Student model for storing student information."""

    __tablename__ = "student"

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
    created_at = db.Column(db.DateTime, server_default=func.now())
    created_by = db.Column(db.String(20), nullable=False)
    updated_at = db.Column(db.DateTime, onupdate=func.now())
    updated_by = db.Column(db.String(20), nullable=True)

    # Relationships
    class_details = db.relationship("ClassDetails", back_populates="student", cascade="all, delete-orphan")
    fee_records = db.relationship("Fee", back_populates="student", cascade="all, delete-orphan")
    fee_breakdown = db.relationship("FeeBreakdown", back_populates="student", cascade="all, delete-orphan")

    # Indexes for performance
    __table_args__ = (
        Index("ix_student_admission_number", "admission_number"),
        Index("ix_student_student_name", "student_name"),
        Index("ix_student_father_name", "father_name"),
    )

    def __repr__(self) -> str:
        """String representation of the Student model.

        Returns:
            String representation with PEN number, name, and father's name
        """
        return f"Student('{self.pen_num}', '{self.student_name}', '{self.father_name}')"

    @hybrid_property
    def full_name(self) -> str:
        """Get full student name.

        Returns:
            Student's full name
        """
        return self.student_name

    @hybrid_property
    def age(self) -> Optional[int]:
        """Calculate student age based on date of birth.

        Returns:
            Age in years or None if date of birth is not set
        """
        if self.date_of_birth:
            today = date.today()
            return today.year - self.date_of_birth.year - (
                (today.month, today.day) < (self.date_of_birth.month, self.date_of_birth.day)
            )
        return None

    @property
    def masked_aadhar(self) -> str:
        """Return a masked version of the Aadhar number for display.

        Returns:
            Masked Aadhar number (only last 4 digits visible)
        """
        if not self.aadhar_number:
            return "N/A"
        aadhar_str = str(self.aadhar_number)
        masked_length = max(0, len(aadhar_str) - 4)
        return "X" * masked_length + aadhar_str[-4:] if len(aadhar_str) > 4 else aadhar_str

    # Method to handle date parsing when setting attributes
    def __setattr__(self, key: str, value: Any) -> None:
        """Override setattr to handle date parsing for date fields.

        Args:
            key: Attribute name
            value: Value to set
        """
        if key in ["date_of_birth", "date_of_joining"] and isinstance(value, str):
            value = parse_date_from_string(value, key)
        super().__setattr__(key, value)

    @validates("pen_num", "admission_number", "aadhar_number")
    def validate_numbers(self, key: str, value: Any) -> int:
        """Validate numeric fields.

        Args:
            key: Field name
            value: Value to validate

        Returns:
            Validated numeric value

        Raises:
            ValueError: If value is invalid
        """
        if not value:
            raise ValueError(f"{key} cannot be empty")

        try:
            val = int(value)
            if val <= 0:
                raise ValueError(f"{key} must be a positive number")
            
            # Specific validation for Aadhar number (12 digits)
            if key == "aadhar_number" and len(str(val)) != 12:
                raise ValueError("Aadhar number must be 12 digits")
                
            return val
        except (ValueError, TypeError):
            raise ValueError(f"{key} must be a valid number")

    @validates("student_name", "father_name", "mother_name", "village")
    def validate_text_fields(self, key: str, value: str) -> str:
        """Validate text fields.

        Args:
            key: Field name
            value: Value to validate

        Returns:
            Validated text value

        Raises:
            ValueError: If value is invalid
        """
        if not value or not value.strip():
            raise ValueError(f"{key} cannot be empty")
        
        # Sanitize the input
        sanitized = value.strip()
        
        # Check for minimum length
        if len(sanitized) < 2:
            raise ValueError(f"{key} must be at least 2 characters long")
            
        return sanitized

    @validates("gender")
    def validate_gender(self, key: str, value: str) -> str:
        """Validate gender field.

        Args:
            key: Field name
            value: Value to validate

        Returns:
            Validated gender value

        Raises:
            ValueError: If value is invalid
        """
        valid_genders = ["male", "female", "other"]
        if not value or value.lower() not in valid_genders:
            raise ValueError(f"Gender must be one of: {', '.join(valid_genders)}")
        return value.capitalize()

    @validates("contact_number")
    def validate_contact(self, key: str, value: str) -> str:
        """Validate contact number.

        Args:
            key: Field name
            value: Value to validate

        Returns:
            Validated contact number

        Raises:
            ValueError: If value is invalid
        """
        if not value or not value.strip():
            raise ValueError("Contact number cannot be empty")
            
        # Remove any non-numeric characters except +
        cleaned = re.sub(r"[^\d+]", "", value)
        
        # Check for valid phone format
        if not re.match(r"^\+?\d{10,15}$", cleaned):
            raise ValueError("Contact number must be 10-15 digits with optional + prefix")
            
        return cleaned


@event.listens_for(Student, "before_insert")
@event.listens_for(Student, "before_update")
def before_student_save(mapper, connection, target):
    """Event listener for Student model before saving.

    Args:
        mapper: SQLAlchemy mapper
        connection: SQLAlchemy connection
        target: Target Student instance
    """
    set_user_metadata(target)
    target.updated_at = datetime.now()


class Transport(db.Model):
    """Transport model for storing transport routes and pickup points."""

    __tablename__ = "transport"

    transport_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    pick_up_point = db.Column(db.String(50), nullable=False, unique=True)
    route_number = db.Column(db.Integer, nullable=False)

    # Track user actions
    created_at = db.Column(db.DateTime, server_default=func.now())
    created_by = db.Column(db.String(20), nullable=False)
    updated_at = db.Column(db.DateTime, onupdate=func.now())
    updated_by = db.Column(db.String(20), nullable=True)

    # Relationships
    fee_records = db.relationship("Fee", back_populates="transport")

    # Indexes for performance
    __table_args__ = (Index("ix_transport_route_number", "route_number"),)

    def __repr__(self) -> str:
        """String representation of the Transport model.

        Returns:
            String representation with transport ID, pickup point, and route number
        """
        return f"Transport('{self.transport_id}', '{self.pick_up_point}', '{self.route_number}')"

    @validates("pick_up_point")
    def validate_pickup_point(self, key: str, value: str) -> str:
        """Validate pickup point.

        Args:
            key: Field name
            value: Value to validate

        Returns:
            Validated pickup point

        Raises:
            ValueError: If value is invalid
        """
        if not value or not value.strip():
            raise ValueError("Pickup point cannot be empty")
        return value.strip()

    @validates("route_number")
    def validate_route_number(self, key: str, value: Any) -> int:
        """Validate route number.

        Args:
            key: Field name
            value: Value to validate

        Returns:
            Validated route number

        Raises:
            ValueError: If value is invalid
        """
        try:
            val = int(value)
            if val <= 0:
                raise ValueError("Route number must be positive")
            return val
        except (ValueError, TypeError):
            raise ValueError("Route number must be a valid integer")


@event.listens_for(Transport, "before_insert")
@event.listens_for(Transport, "before_update")
def before_transport_save(mapper, connection, target):
    """Event listener for Transport model before saving.

    Args:
        mapper: SQLAlchemy mapper
        connection: SQLAlchemy connection
        target: Target Transport instance
    """
    set_user_metadata(target)
    target.updated_at = datetime.now()


class ClassDetails(db.Model):
    """ClassDetails model for storing student class information."""

    __tablename__ = "class_details"

    pen_num = db.Column(db.BigInteger, db.ForeignKey("student.pen_num", ondelete="CASCADE"), primary_key=True)
    year = db.Column(db.Integer, primary_key=True, nullable=False)
    current_class = db.Column(db.Integer, nullable=False)
    section = db.Column(db.String(2), nullable=False)
    roll_number = db.Column(db.Integer, nullable=False)
    photo_id = db.Column(db.Integer, unique=True, nullable=False)
    language = db.Column(db.String(50), nullable=False)
    vocational = db.Column(db.String(50), nullable=False)
    currently_enrolled = db.Column(db.Boolean, default=True)

    # Relationships
    student = db.relationship("Student", back_populates="class_details")

    # Track user actions
    created_at = db.Column(db.DateTime, server_default=func.now())
    created_by = db.Column(db.String(20), nullable=False)
    updated_at = db.Column(db.DateTime, onupdate=func.now())
    updated_by = db.Column(db.String(20), nullable=True)

    # Indexes for performance
    __table_args__ = (
        Index("ix_class_details_year", "year"),
        Index("ix_class_details_current_class", "current_class"),
        Index("ix_class_details_section", "section"),
    )

    def __repr__(self) -> str:
        """String representation of the ClassDetails model.

        Returns:
            String representation with PEN number, year, class, and section
        """
        return f"ClassDetails('{self.pen_num}', '{self.year}', '{self.current_class}', '{self.section}')"

    @hybrid_property
    def class_section(self) -> str:
        """Get combined class and section.

        Returns:
            Combined class and section string
        """
        return f"{self.current_class}-{self.section}"

    @validates("year")
    def validate_year(self, key: str, value: Any) -> int:
        """Validate year.

        Args:
            key: Field name
            value: Value to validate

        Returns:
            Validated year

        Raises:
            ValueError: If value is invalid
        """
        try:
            val = int(value)
            current_year = datetime.now().year
            if val < 2000 or val > current_year + 1:
                raise ValueError(f"Year must be between 2000 and {current_year + 1}")
            return val
        except (ValueError, TypeError):
            raise ValueError("Year must be a valid integer")

    @validates("current_class", "roll_number", "photo_id")
    def validate_numeric_fields(self, key: str, value: Any) -> int:
        """Validate numeric fields.

        Args:
            key: Field name
            value: Value to validate

        Returns:
            Validated numeric value

        Raises:
            ValueError: If value is invalid
        """
        try:
            val = int(value)
            if val <= 0:
                raise ValueError(f"{key} must be positive")
                
            # Class-specific validation
            if key == "current_class" and (val < 1 or val > 12):
                raise ValueError("Class must be between 1 and 12")
                
            return val
        except (ValueError, TypeError):
            raise ValueError(f"{key} must be a valid integer")

    @validates("section")
    def validate_section(self, key: str, value: str) -> str:
        """Validate section.

        Args:
            key: Field name
            value: Value to validate

        Returns:
            Validated section

        Raises:
            ValueError: If value is invalid
        """
        if not value or not value.strip():
            raise ValueError("Section cannot be empty")
            
        section = value.strip().upper()
        if not re.match(r"^[A-Z]$", section):
            raise ValueError("Section must be a single uppercase letter")
            
        return section

    @validates("language", "vocational")
    def validate_subject_fields(self, key: str, value: str) -> str:
        """Validate language and vocational fields.

        Args:
            key: Field name
            value: Value to validate

        Returns:
            Validated subject field

        Raises:
            ValueError: If value is invalid
        """
        if not value or not value.strip():
            raise ValueError(f"{key} cannot be empty")
        return value.strip()


@event.listens_for(ClassDetails, "before_insert")
@event.listens_for(ClassDetails, "before_update")
def before_classdetails_save(mapper, connection, target):
    """Event listener for ClassDetails model before saving.

    Args:
        mapper: SQLAlchemy mapper
        connection: SQLAlchemy connection
        target: Target ClassDetails instance
    """
    set_user_metadata(target)
    target.updated_at = datetime.now()


class Fee(db.Model):
    """Fee model for storing student fee information."""

    __tablename__ = "fee"

    pen_num = db.Column(db.BigInteger, db.ForeignKey("student.pen_num", ondelete="CASCADE"), primary_key=True)
    year = db.Column(db.Integer, primary_key=True, nullable=False)
    school_fee = db.Column(db.Integer, nullable=False)
    concession_reason = db.Column(db.String(50), nullable=True)
    school_fee_concession = db.Column(db.Integer, nullable=False, default=0)
    transport_used = db.Column(db.Boolean, nullable=False, default=False)
    application_fee = db.Column(db.Integer, nullable=False)
    transport_fee = db.Column(db.Integer, nullable=True)
    transport_fee_concession = db.Column(db.Integer, nullable=True, default=0)
    transport_id = db.Column(db.Integer, db.ForeignKey("transport.transport_id", ondelete="SET NULL"), nullable=True)

    # Relationships
    student = db.relationship("Student", back_populates="fee_records")
    transport = db.relationship("Transport", back_populates="fee_records")

    # Track user actions
    created_at = db.Column(db.DateTime, server_default=func.now())
    created_by = db.Column(db.String(20), nullable=False)
    updated_at = db.Column(db.DateTime, onupdate=func.now())
    updated_by = db.Column(db.String(20), nullable=True)

    # Indexes for performance
    __table_args__ = (
        Index("ix_fee_year", "year"),
        Index("ix_fee_transport_used", "transport_used"),
    )

    @staticmethod
    def calculate_school_fee_concession(reason: Optional[str], school_fee: int) -> int:
        """Calculate school fee concession based on reason.

        Args:
            reason: Concession reason
            school_fee: Original school fee

        Returns:
            Calculated concession amount
        """
        if not reason or not school_fee:
            return 0
            
        concession_map = {
            "Staff": 0.5,
            "Sibbling": 0.1,
            "Sibling": 0.1,
            "OTP": 0.1,
            "General": 0.1,
            "TF": 0.05,
            "FP": 0.2,
            "EC": 0.15,
            "SC": 0.25,
        }
        
        # Safely get concession rate with default of 0
        concession_rate = concession_map.get(reason, 0)
        
        # Calculate and round to integer
        return int(school_fee * concession_rate)

    @hybrid_property
    def total_fee(self) -> int:
        """Calculate total fee after concessions.

        Returns:
            Total fee amount
        """
        school_fee_after_concession = self.school_fee - (self.school_fee_concession or 0)
        
        transport_fee_after_concession = 0
        if self.transport_used and self.transport_fee:
            transport_fee_after_concession = self.transport_fee - (self.transport_fee_concession or 0)
            
        return school_fee_after_concession + transport_fee_after_concession + self.application_fee

    @validates("school_fee", "application_fee")
    def validate_fees(self, key: str, value: Any) -> int:
        """Validate fee amounts.

        Args:
            key: Field name
            value: Value to validate

        Returns:
            Validated fee amount

        Raises:
            ValueError: If value is invalid
        """
        try:
            val = int(value)
            if val < 0:
                raise ValueError(f"{key} cannot be negative")
            return val
        except (ValueError, TypeError):
            raise ValueError(f"{key} must be a valid integer")

    @validates("transport_fee", "transport_fee_concession")
    def validate_transport_fees(self, key: str, value: Any) -> Optional[int]:
        """Validate transport fee amounts.

        Args:
            key: Field name
            value: Value to validate

        Returns:
            Validated transport fee amount or None

        Raises:
            ValueError: If value is invalid
        """
        if value is None:
            return None
            
        try:
            val = int(value)
            if val < 0:
                raise ValueError(f"{key} cannot be negative")
            return val
        except (ValueError, TypeError):
            raise ValueError(f"{key} must be a valid integer or None")

    @validates("concession_reason")
    def validate_concession_reason(self, key: str, value: Optional[str]) -> Optional[str]:
        """Validate concession reason.

        Args:
            key: Field name
            value: Value to validate

        Returns:
            Validated concession reason or None

        Raises:
            ValueError: If value is invalid
        """
        if not value:
            return None
            
        valid_reasons = ["Staff", "Sibbling", "Sibling", "OTP", "General", "TF", "FP", "EC", "SC"]
        if value not in valid_reasons:
            raise ValueError(f"Concession reason must be one of: {', '.join(valid_reasons)}")
            
        return value

    def __repr__(self) -> str:
        """String representation of the Fee model.

        Returns:
            String representation with key fields
        """
        return (
            f"Fee(pen_num={self.pen_num}, year={self.year}, school_fee={self.school_fee}, "
            f"concession='{self.concession_reason}', transport_used={self.transport_used})"
        )


@event.listens_for(Fee, "before_insert")
@event.listens_for(Fee, "before_update")
def before_fee_save(mapper, connection, target):
    """Event listener for Fee model before saving.

    Args:
        mapper: SQLAlchemy mapper
        connection: SQLAlchemy connection
        target: Target Fee instance
    """
    try:
        # Calculate school fee concession
        target.school_fee_concession = Fee.calculate_school_fee_concession(
            target.concession_reason, target.school_fee
        )

        # If transport is not used, reset related fields
        if not target.transport_used:
            target.transport_fee = 0
            target.transport_fee_concession = 0
            target.transport_id = None

        set_user_metadata(target)
        target.updated_at = datetime.now()
    except Exception as e:
        logger.error(f"Error in before_fee_save: {e}")
        raise


class FeeBreakdown(db.Model):
    """FeeBreakdown model for storing fee payment details."""

    __tablename__ = "fee_breakdown"

    pen_num = db.Column(db.BigInteger, db.ForeignKey("student.pen_num", ondelete="CASCADE"), primary_key=True)
    year = db.Column(db.Integer, primary_key=True, nullable=False)
    fee_type = db.Column(db.String(50), primary_key=True, nullable=False)
    term = db.Column(db.String(5), primary_key=True, nullable=False)
    payment_type = db.Column(db.String(15), primary_key=True, nullable=False)
    paid = db.Column(db.Numeric(10, 2), nullable=False, default=0)
    due = db.Column(db.Numeric(10, 2), nullable=False, default=0)
    receipt_no = db.Column(db.Integer, nullable=True)
    fee_paid_date = db.Column(db.Date, nullable=True)

    # Relationships
    student = db.relationship("Student", back_populates="fee_breakdown")

    # Track user actions
    created_at = db.Column(db.DateTime, server_default=func.now())
    created_by = db.Column(db.String(20), nullable=False)
    updated_at = db.Column(db.DateTime, onupdate=func.now())
    updated_by = db.Column(db.String(20), nullable=True)

    # Indexes for performance
    __table_args__ = (
        Index("ix_fee_breakdown_year", "year"),
        Index("ix_fee_breakdown_fee_type", "fee_type"),
        Index("ix_fee_breakdown_term", "term"),
    )

    def __setattr__(self, key: str, value: Any) -> None:
        """Override setattr to handle date parsing for date fields.

        Args:
            key: Attribute name
            value: Value to set
        """
        if key == "fee_paid_date" and isinstance(value, str):
            value = parse_date_from_string(value, key)
        super().__setattr__(key, value)

    @validates("year")
    def validate_year(self, key: str, value: Any) -> int:
        """Validate year.

        Args:
            key: Field name
            value: Value to validate

        Returns:
            Validated year

        Raises:
            ValueError: If value is invalid
        """
        try:
            val = int(value)
            current_year = datetime.now().year
            if val < 2000 or val > current_year + 1:
                raise ValueError(f"Year must be between 2000 and {current_year + 1}")
            return val
        except (ValueError, TypeError):
            raise ValueError("Year must be a valid integer")

    @validates("fee_type")
    def validate_fee_type(self, key: str, value: str) -> str:
        """Validate fee type.

        Args:
            key: Field name
            value: Value to validate

        Returns:
            Validated fee type

        Raises:
            ValueError: If value is invalid
        """
        valid_fee_types = ["School", "Transport", "Application", "Other"]
        if not value or value not in valid_fee_types:
            raise ValueError(f"Fee type must be one of: {', '.join(valid_fee_types)}")
        return value

    @validates("term")
    def validate_term(self, key: str, value: str) -> str:
        """Validate term.

        Args:
            key: Field name
            value: Value to validate

        Returns:
            Validated term

        Raises:
            ValueError: If value is invalid
        """
        valid_terms = ["Q1", "Q2", "Q3", "Q4", "Full"]
        if not value or value not in valid_terms:
            raise ValueError(f"Term must be one of: {', '.join(valid_terms)}")
        return value

    @validates("payment_type")
    def validate_payment_type(self, key: str, value: str) -> str:
        """Validate payment type.

        Args:
            key: Field name
            value: Value to validate

        Returns:
            Validated payment type

        Raises:
            ValueError: If value is invalid
        """
        valid_payment_types = ["Cash", "Cheque", "Card", "Online", "Bank Transfer"]
        if not value or value not in valid_payment_types:
            raise ValueError(f"Payment type must be one of: {', '.join(valid_payment_types)}")
        return value

    @validates("paid", "due")
    def validate_amount(self, key: str, value: Any) -> float:
        """Validate paid and due amounts.

        Args:
            key: Field name
            value: Value to validate

        Returns:
            Validated numeric amount

        Raises:
            ValueError: If value is invalid
        """
        try:
            val = float(value)
            if val < 0:
                raise ValueError(f"{key} cannot be negative")
            return val
        except (ValueError, TypeError):
            raise ValueError(f"{key} must be a valid number")

    @validates("receipt_no")
    def validate_receipt_no(self, key: str, value: Any) -> Optional[int]:
        """Validate receipt number.

        Args:
            key: Field name
            value: Value to validate

        Returns:
            Validated receipt number or None

        Raises:
            ValueError: If value is invalid
        """
        if value is None:
            return None
            
        try:
            val = int(value)
            if val <= 0:
                raise ValueError("Receipt number must be positive")
            return val
        except (ValueError, TypeError):
            raise ValueError("Receipt number must be a valid integer or None")

    def __repr__(self) -> str:
        """String representation of the FeeBreakdown model.

        Returns:
            String representation with key fields
        """
        return (
            f"FeeBreakdown(pen_num={self.pen_num}, year={self.year}, "
            f"fee_type='{self.fee_type}', term='{self.term}', paid={self.paid}, due={self.due})"
        )


@event.listens_for(FeeBreakdown, "before_insert")
@event.listens_for(FeeBreakdown, "before_update")
def before_feebreakdown_save(mapper, connection, target):
    """Event listener for FeeBreakdown model before saving.

    Args:
        mapper: SQLAlchemy mapper
        connection: SQLAlchemy connection
        target: Target FeeBreakdown instance
    """
    set_user_metadata(target)
    target.updated_at = datetime.now()


class ActivityLog(db.Model):
    """ActivityLog model for tracking user activities."""

    __tablename__ = "activity_log"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    action_type = db.Column(db.String(50), nullable=False)  # e.g., "added", "updated", "deleted"
    entity_type = db.Column(db.String(50), nullable=False)  # e.g., "Student", "Fee", "Transport"
    entity_id = db.Column(db.String(50), nullable=False)  # Primary key of the affected entity
    description = db.Column(db.String(255), nullable=False)  # Human-readable description
    ip_address = db.Column(db.String(45), nullable=True)  # Store IP address for security auditing
    user_agent = db.Column(db.String(255), nullable=True)  # Store browser/client info
    created_at = db.Column(db.DateTime, default=datetime.now)

    # Relationship
    user = db.relationship("User", backref=db.backref("activities", lazy=True))

    # Indexes for performance
    __table_args__ = (
        Index("ix_activity_log_user_id", "user_id"),
        Index("ix_activity_log_action_type", "action_type"),
        Index("ix_activity_log_entity_type", "entity_type"),
        Index("ix_activity_log_created_at", "created_at"),
    )

    def __repr__(self) -> str:
        """String representation of the ActivityLog model.

        Returns:
            String representation with action, entity type, and entity ID
        """
        return f"Activity('{self.action_type}', '{self.entity_type}', '{self.entity_id}')"

    @validates("action_type")
    def validate_action_type(self, key: str, value: str) -> str:
        """Validate action type.

        Args:
            key: Field name
            value: Value to validate

        Returns:
            Validated action type

        Raises:
            ValueError: If value is invalid
        """
        valid_actions = ["added", "updated", "deleted", "viewed", "exported", "imported", "login", "logout", "failed_login"]
        if not value or value.lower() not in [a.lower() for a in valid_actions]:
            raise ValueError(f"Action type must be one of: {', '.join(valid_actions)}")
        return value.lower()

    @validates("entity_type")
    def validate_entity_type(self, key: str, value: str) -> str:
        """Validate entity type.

        Args:
            key: Field name
            value: Value to validate

        Returns:
            Validated entity type

        Raises:
            ValueError: If value is invalid
        """
        valid_entities = ["Student", "Fee", "Transport", "ClassDetails", "FeeBreakdown", "User", "System"]
        if not value or value not in valid_entities:
            raise ValueError(f"Entity type must be one of: {', '.join(valid_entities)}")
        return value

    @validates("description")
    def validate_description(self, key: str, value: str) -> str:
        """Validate description.

        Args:
            key: Field name
            value: Value to validate

        Returns:
            Validated description

        Raises:
            ValueError: If value is invalid
        """
        if not value or not value.strip():
            raise ValueError("Description cannot be empty")
            
        # Limit description length
        if len(value) > 255:
            return value[:252] + "..."
            
        return value
