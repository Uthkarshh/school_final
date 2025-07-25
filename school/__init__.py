"""Initialize and configure the Flask application."""

import os
import secrets
import time
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
import atexit

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

# Initialize Flask extensions
db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
csrf = CSRFProtect()
limiter = None
scheduler = None

def init_database():
    """Initialize SQLite database connection."""
    # Get database path from environment or use default
    db_path = os.getenv("DATABASE_PATH", "school_fee.db")
    
    # Ensure the directory exists
    db_dir = os.path.dirname(os.path.abspath(db_path))
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir)
    
    # Return SQLite database URL
    db_url = f"sqlite:///{os.path.abspath(db_path)}"
    logger.info(f"Using SQLite database: {db_url}")
    
    return db_url

def _configure_security(app, is_production):
    """Configure security settings for the application."""
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
    """Configure database settings for the application."""
    db_url = init_database()
    app.config["SQLALCHEMY_DATABASE_URI"] = db_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    # SQLite-specific configuration
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
        "connect_args": {"check_same_thread": False}  # Allow SQLite to be used across threads
    }

def _configure_session(app, is_production):
    """Configure session settings for the application."""
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=1)
    app.config["SESSION_COOKIE_SECURE"] = is_production
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    # Configure server-side session storage
    app.config["SESSION_TYPE"] = "filesystem"
    app.config["SESSION_PERMANENT"] = True
    app.config["SESSION_USE_SIGNER"] = True

    # Create session directory if it doesn't exist
    session_dir = Path(os.getcwd()) / "flask_session"
    app.config["SESSION_FILE_DIR"] = str(session_dir)
    session_dir.mkdir(exist_ok=True)

def _initialize_extensions(app):
    """Initialize Flask extensions with the app."""
    db.init_app(app)
    bcrypt.init_app(app)
    
    login_manager.login_view = "auth_bp.login"
    login_manager.login_message_category = "info"
    login_manager.session_protection = "strong"
    login_manager.init_app(app)
    
    csrf.init_app(app)
    Session(app)

    # Configure login manager unauthorized handler
    @login_manager.unauthorized_handler
    def unauthorized():
        return jsonify({"error": "Unauthorized access"}), 401

def _configure_rate_limiting(app):
    """Configure rate limiting if available."""
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

def _configure_backup_scheduler(app):
    """Configure the backup scheduler."""
    global scheduler
    
    # Check if backup is enabled
    backup_enabled = os.getenv("BACKUP_ENABLED", "true").lower() == "true"
    if not backup_enabled:
        logger.info("Backup scheduler disabled via environment variable")
        return None
    
    try:
        from school.backup_service import BackupService
        
        scheduler = BackgroundScheduler()
        backup_service = BackupService(app)
        
        # Schedule backup at midnight every day
        scheduler.add_job(
            func=backup_service.run_nightly_backup,
            trigger=CronTrigger(hour=0, minute=0),  # Run at 12:00 AM
            id='nightly_backup',
            name='Nightly Database Backup to Google Sheets',
            replace_existing=True
        )
        
        scheduler.start()
        logger.info("Backup scheduler started successfully")
        
        # Shut down the scheduler when exiting the app
        atexit.register(lambda: scheduler.shutdown())
        
        return scheduler
        
    except ImportError as e:
        logger.error(f"Failed to import BackupService: {e}")
        return None
    except Exception as e:
        logger.error(f"Failed to configure backup scheduler: {e}")
        return None

def _register_error_handlers(app):
    """Register error handlers for the application."""
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
    """Register routes, blueprints, and template configurations."""
    # Basic health check route
    @app.route('/health')
    def health_check():
        """Simple health check endpoint."""
        return jsonify({"status": "ok"}), 200
    
    # Register template filters and globals
    @app.context_processor
    def utility_processor():
        return {
            'hasattr': hasattr,
            'isinstance': isinstance,
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
        
        # Add response headers
        @app.after_request
        def add_response_headers(response):
            """Add security and caching headers to responses."""
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'SAMEORIGIN'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            
            if 'Cache-Control' not in response.headers and request.path.startswith('/static'):
                response.headers['Cache-Control'] = 'public, max-age=31536000'
                
            return response

def create_app(testing=False):
    """Create and configure the Flask application."""
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
    
    # Configure backup scheduler (only if not testing)
    if not testing:
        global scheduler
        scheduler = _configure_backup_scheduler(app)

    return app, db, bcrypt, login_manager, csrf, limiter

# Create the application instance
app, db, bcrypt, login_manager, csrf, limiter = create_app()
