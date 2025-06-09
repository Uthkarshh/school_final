"""Initialize and configure the Flask application."""

import os
import re
import secrets
import socket
import time
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlparse

import psycopg2
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from sqlalchemy_utils import create_database, database_exists

import logging

# Configure logging first
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("app.log"),
    ],
)
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

# Initialize Flask extensions outside of create_app to make them available at module level
# but initialize them with the app inside create_app
db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
csrf = CSRFProtect()
limiter = None  # This will be initialized in create_app if available


def is_docker():
    """Check if the application is running in a Docker container."""
    try:
        return os.path.exists("/.dockerenv") or bool(socket.gethostbyname("db"))
    except socket.gaierror:
        return False


def validate_db_name(db_name):
    """Validate database name to prevent SQL injection."""
    if not re.match(r"^[a-zA-Z0-9_]+$", db_name):
        raise ValueError("Invalid database name")
    return db_name


def _create_database(db_url, db_name):
    """Create database if it doesn't exist.
    
    Args:
        db_url: Full database URL
        db_name: Name of the database to create
    """
    # Parse the DATABASE_URL to get components
    db_parts = db_url.split("/")
    db_connection_string = "/".join(db_parts[:-1])

    # Connect to default postgres database to create our new database
    conn = psycopg2.connect(f"{db_connection_string}/postgres")
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)

    try:
        with conn.cursor() as cursor:
            cursor.execute(f"CREATE DATABASE {db_name}")
            logger.info(f"Database '{db_name}' created successfully")
    except Exception as e:
        logger.error(f"Error creating database: {e}")
        raise
    finally:
        conn.close()


def init_database():
    """Initialize the database connection with retry logic."""
    # Determine the database URL based on environment
    if is_docker():
        # In Docker, use the environment variable passed in docker-compose
        db_url = os.getenv(
            "DATABASE_URL", "postgresql://postgres:postgres@db:5432/school_fee_db"
        )
    else:
        # Outside Docker, use localhost connection
        db_url = os.getenv(
            "DATABASE_URL_LOCAL",
            "postgresql://postgres:postgres@localhost:5432/school_fee_db",
        )

    logger.info(f"Using database URL: {db_url}")

    # Parse DB URL for security
    parsed_url = urlparse(db_url)
    db_name = parsed_url.path.lstrip("/")

    # Validate database name
    try:
        validate_db_name(db_name)
    except ValueError as e:
        logger.error(f"Database name validation failed: {e}")
        raise

    # Add retry logic for Docker container startup timing
    max_retries = 5
    
    for retry_count in range(max_retries):
        try:
            # Check if the database exists
            if not database_exists(db_url):
                logger.info("Database does not exist. Creating database...")
                _create_database(db_url, db_name)
            else:
                logger.info("Database already exists")

            # Test the connection to make sure it works
            conn = psycopg2.connect(db_url)
            conn.close()
            logger.info("Successfully connected to database")

            return db_url

        except Exception as e:
            if retry_count < max_retries - 1:
                logger.warning(
                    f"Database connection attempt {retry_count + 1} failed. "
                    f"Retrying in 5 seconds... Error: {e}"
                )
                time.sleep(5)
            else:
                logger.error(f"Failed to connect to database after {max_retries} attempts: {e}")
                raise


def _configure_security(app, is_production):
    """Configure security settings for the application.
    
    Args:
        app: Flask application instance
        is_production: Boolean indicating if running in production
    """
    # Secret key for session security from environment variable
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
    if not app.config["SECRET_KEY"]:
        app.config["SECRET_KEY"] = secrets.token_hex(32)
        logger.warning(
            "Using a randomly generated secret key. "
            "For production, set SECRET_KEY in environment variables."
        )

    # CSRF protection
    app.config["WTF_CSRF_ENABLED"] = True
    app.config["WTF_CSRF_TIME_LIMIT"] = 3600  # 1 hour

    # Security headers
    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        if is_production:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


def _configure_database(app):
    """Configure database settings for the application.
    
    Args:
        app: Flask application instance
    """
    db_url = init_database()
    app.config["SQLALCHEMY_DATABASE_URI"] = db_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": True,
        "pool_recycle": 300,  # Recycle connections after 5 minutes
        "pool_timeout": 30,  # Connection timeout of 30 seconds
        "pool_size": 10,  # Maximum of 10 connections
        "max_overflow": 5,  # Allow 5 connections beyond pool_size
    }


def _configure_session(app, is_production):
    """Configure session settings for the application.
    
    Args:
        app: Flask application instance
        is_production: Boolean indicating if running in production
    """
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=1)
    app.config["SESSION_COOKIE_SECURE"] = is_production  # Secure in production
    app.config["SESSION_COOKIE_HTTPONLY"] = True  # Prevent JavaScript access
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # CSRF protection

    # Configure server-side session storage
    app.config["SESSION_TYPE"] = "filesystem"
    app.config["SESSION_PERMANENT"] = True
    app.config["SESSION_USE_SIGNER"] = True  # Sign the session cookie

    # Create session directory if it doesn't exist
    session_dir = Path(os.getcwd()) / "flask_session"
    app.config["SESSION_FILE_DIR"] = str(session_dir)
    session_dir.mkdir(exist_ok=True)


def _initialize_extensions(app):
    """Initialize Flask extensions with the app.
    
    Args:
        app: Flask application instance
    """
    db.init_app(app)
    bcrypt.init_app(app)
    
    login_manager.login_view = "auth_bp.login"
    login_manager.login_message_category = "info"
    login_manager.session_protection = "strong"  # Enhanced session protection
    login_manager.init_app(app)
    
    csrf.init_app(app)
    Session(app)

    # Configure login manager unauthorized handler
    @login_manager.unauthorized_handler
    def unauthorized():
        return jsonify({"error": "Unauthorized access"}), 401


def _configure_rate_limiting(app):
    """Configure rate limiting if available.
    
    Args:
        app: Flask application instance
        
    Returns:
        Limiter instance or None if not available
    """
    global limiter
    try:
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address

        limiter = Limiter(
            get_remote_address,
            app=app,
            default_limits=["200 per day", "50 per hour"],
            storage_uri="memory://",
        )
        return limiter
    except ImportError:
        logger.warning("Flask-Limiter not installed. Rate limiting disabled.")
        return None


def _register_error_handlers(app):
    """Register error handlers for the application.
    
    Args:
        app: Flask application instance
    """
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({"error": "Bad request"}), 400

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({"error": "Resource not found"}), 404

    @app.errorhandler(500)
    def server_error(error):
        logger.error(f"Internal server error: {error}")
        return jsonify({"error": "Internal server error"}), 500


def _register_routes_and_blueprints(app):
    """Register routes, blueprints, and template configurations.
    
    Args:
        app: Flask application instance
    """
    # Basic health check route
    @app.route('/health')
    def health_check():
        """Simple health check endpoint."""
        return jsonify({"status": "ok"}), 200
    
    # Register template filters and globals
    @app.context_processor
    def utility_processor():
        return {
            'hasattr': hasattr,  # Make hasattr available in templates
            'isinstance': isinstance,  # Optionally add isinstance too
        }

    # Import routes here to avoid circular imports
    with app.app_context():
        from school.routes import (
            auth_bp, user_bp, admin_bp, student_bp, fee_bp, transport_bp, report_bp,
            home, about, format_datetime
        )
        
        # Register template filter
        app.jinja_env.filters['datetime'] = format_datetime
        
        # Register main routes
        app.add_url_rule('/', view_func=home)
        app.add_url_rule('/home', view_func=home)
        app.add_url_rule('/about', view_func=about)
        
        # Register blueprints
        blueprints = [auth_bp, user_bp, admin_bp, student_bp, fee_bp, transport_bp, report_bp]
        for blueprint in blueprints:
            app.register_blueprint(blueprint)
        
        # Add caching headers for static files and security headers
        @app.after_request
        def add_response_headers(response):
            """Add security and caching headers to responses."""
            # Security headers (additional to the ones in _configure_security)
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'SAMEORIGIN'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            
            # Cache static files
            if 'Cache-Control' not in response.headers and request.path.startswith('/static'):
                response.headers['Cache-Control'] = 'public, max-age=31536000'
                
            return response


def create_app(testing=False):
    """Create and configure the Flask application.
    
    Args:
        testing: Boolean indicating if app is being created for testing
        
    Returns:
        Tuple containing (app, db, bcrypt, login_manager, csrf, limiter)
    """
    app = Flask(__name__)

    # Environment configuration
    env = os.getenv("FLASK_ENV", "development")
    is_production = env == "production"

    # Configure all application components
    _configure_security(app, is_production)
    _configure_database(app)
    _configure_session(app, is_production)
    _initialize_extensions(app)
    
    # Configure rate limiting
    global limiter
    limiter = _configure_rate_limiting(app)

    # Register routes, blueprints, and error handlers
    _register_routes_and_blueprints(app)
    _register_error_handlers(app)

    return app, db, bcrypt, login_manager, csrf, limiter


# Create the application instance
app, db, bcrypt, login_manager, csrf, limiter = create_app()
