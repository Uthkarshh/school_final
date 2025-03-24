from school import app, db

# Create database tables within application context
with app.app_context():
    db.create_all()
    print("Database tables created successfully!")

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)  # Bind to all interfaces
