from flask_sqlalchemy import SQLAlchemy
from flask import Flask, jsonify
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from dotenv import load_dotenv
import os
from flask_wtf.csrf import CSRFProtect
from datetime import timedelta

load_dotenv()

app = Flask(__name__)

# Secret key for session security
app.config['SECRET_KEY'] = '7fea38684e057829da404a986b42f373'

# PostgreSQL Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
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
