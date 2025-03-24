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

# Load environment variables
load_dotenv()

# Check if we're running in Docker - simplified approach
def is_docker():
    # Try to resolve the 'db' hostname which should only be possible in Docker
    try:
        socket.gethostbyname('db')
        return True
    except:
        return False

# Database initialization function
def init_database():
    # Determine the database URL based on environment
    if is_docker():
        # In Docker, use the environment variable passed in docker-compose
        db_url = os.getenv('DATABASE_URL', 'postgresql://postgres:postgres@db:5432/school_fee_db')
    else:
        # Outside Docker, use localhost connection
        db_url = os.getenv('DATABASE_URL_LOCAL', 'postgresql://uthkarsh:Ruthwik081%40@localhost:5432/school_fee_db')
    
    print(f"Using database URL: {db_url}")
    
    # Add retry logic for Docker container startup timing
    max_retries = 5
    retry_count = 0
    
    while retry_count < max_retries:
        try:
            # Check if the database exists
            if not database_exists(db_url):
                print(f"Database does not exist. Creating database...")
                
                # Parse the DATABASE_URL to get components
                # Extract connection string without database name and the database name
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

# Secret key for session security (from environment variable or default)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', '7fea38684e057829da404a986b42f373')

# Initialize and configure database
db_url = init_database()
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # To suppress warning messages

# Set session timeout
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # Adjust as needed

# Initialize Flask extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.session_protection = "basic"  # Prevents unnecessary logouts
csrf = CSRFProtect(app)
app.config['WTF_CSRF_ENABLED'] = True
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_TYPE'] = 'filesystem'

@login_manager.unauthorized_handler
def unauthorized():
    return jsonify({"error": "Unauthorized access"}), 401  # Prevents login page download

from school import routes
