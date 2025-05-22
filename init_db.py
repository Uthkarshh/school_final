from school import app, db

def init_database():
    """Initialize database tables within application context"""
    with app.app_context():
        db.create_all()
        print("Database tables created successfully!")

if __name__ == "__main__":
    init_database()
