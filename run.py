from school import create_app
import logging
from logging.handlers import RotatingFileHandler
import os

# Create application instance
app, db, bcrypt, login_manager, csrf, limiter = create_app()

def configure_logging(app):
    """Configure application logging with rotation"""
    if not app.debug:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        file_handler = RotatingFileHandler('logs/school.log', maxBytes=10240, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('School Fee Application startup')

def create_tables():
    """Create database tables within application context"""
    with app.app_context():
        db.create_all()
        app.logger.info("Database tables created successfully!")

if __name__ == '__main__':
    # Configure application logging
    configure_logging(app)
    
    # Create database tables
    create_tables()
    
    # Run the application
    # Note: Using debug=True directly as specified in the update
    app.run(
        debug=True,
        host="0.0.0.0",
        # Still including these production-ready settings
        threaded=True,
        use_reloader=True
    )
