from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from dotenv import load_dotenv
import os
from flask_wtf.csrf import CSRFProtect

load_dotenv()

app = Flask(__name__)

# Secret key for session security
app.config['SECRET_KEY'] = '7fea38684e057829da404a986b42f373'

# PostgreSQL Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # To suppress warning messages

# Initialize Flask extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
csrf = CSRFProtect(app)

from school import routes
