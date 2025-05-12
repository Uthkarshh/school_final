from flask_sqlalchemy import SQLAlchemy
from flask import Flask, jsonify
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from dotenv import load_dotenv
import os
from flask_wtf.csrf import CSRFProtect
from datetime import timedelta
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from sqlalchemy_utils import database_exists, create_database
import time
import socket
import re
from urllib.parse import urlparse

# Load environment variables
load_dotenv()

# Check if we're running in Docker - improved approach
def is_docker():
    try:
        # Check for docker container env file
        return os.path.exists('/.dockerenv') or socket.gethostbyname('db')
    except:
        return False

# Database initialization function
def init_database():
    # Determine the database URL based on environment
    if is_docker():
        # In Docker, use the environment variable passed in docker-compose
        db_url = os.getenv('DATABASE_URL', 'postgresql://postgres:postgres@db:5432/school_fee_db')
    else:
        # Outside Docker, use localhost connection - avoid hardcoding credentials
        db_url = os.getenv('DATABASE_URL_LOCAL', 'postgresql://postgres:postgres@localhost:5432/school_fee_db')
    
    print(f"Using database URL: {db_url}")
    
    # Parse DB URL for security
    parsed_url = urlparse(db_url)
    db_name = parsed_url.path.lstrip('/')
    
    # Add retry logic for Docker container startup timing
    max_retries = 5
    retry_count = 0
    
    while retry_count < max_retries:
        try:
            # Check if the database exists
            if not database_exists(db_url):
                print(f"Database does not exist. Creating database...")
                
                # Parse the DATABASE_URL to get components without exposing credentials in logs
                db_parts = db_url.split('/')
                db_name = db_parts[-1]
                db_connection_string = '/'.join(db_parts[:-1])
                
                # Connect to default postgres database to create our new database
                conn = psycopg2.connect(f"{db_connection_string}/postgres")
                conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
                
                try:
                    with conn.cursor() as cursor:
                        cursor.execute(f"CREATE DATABASE {db_name}")
                        print(f"Database '{db_name}' created successfully")
                except Exception as e:
                    print(f"Error creating database: {e}")
                finally:
                    conn.close()
            else:
                print("Database already exists")
            
            # Test the connection to make sure it works
            conn = psycopg2.connect(db_url)
            conn.close()
            print("Successfully connected to database")
            
            return db_url
            
        except Exception as e:
            retry_count += 1
            if retry_count < max_retries:
                print(f"Database connection attempt {retry_count} failed. Retrying in 5 seconds... Error: {e}")
                time.sleep(5)
            else:
                print(f"Failed to connect to database after {max_retries} attempts: {e}")
                raise

# Create Flask application
app = Flask(__name__)

# Secret key for session security from environment variable (improved security)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
if not app.config['SECRET_KEY']:
    # Generate a secure random key if not provided
    import secrets
    app.config['SECRET_KEY'] = secrets.token_hex(32)
    print("WARNING: Using a randomly generated secret key. For production, set SECRET_KEY in environment variables.")

# Initialize and configure database
db_url = init_database()
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Set session timeout and security settings
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
app.config['SESSION_COOKIE_SECURE'] = os.getenv('FLASK_ENV') == 'production'  # Secure in production
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection

# Initialize Flask extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.session_protection = "strong"  # Enhanced session protection
csrf = CSRFProtect(app)
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_TYPE'] = 'filesystem'

# Rate limiting setup (if available)
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://",
    )
except ImportError:
    limiter = None
    print("Flask-Limiter not installed. Rate limiting disabled.")

@login_manager.unauthorized_handler
def unauthorized():
    return jsonify({"error": "Unauthorized access"}), 401

from school import routes
