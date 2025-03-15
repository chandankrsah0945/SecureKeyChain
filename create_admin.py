from app import app, db, bcrypt
from models import User

with app.app_context():
    # Drop all tables (if they exist)
    db.drop_all()

    # Create all tables
    db.create_all()

    # Create an admin user
    admin_username = "@chandankumarsah"
    admin_email = "220101120076@cutm.ac.in"
    admin_password = bcrypt.generate_password_hash("chandan@123").decode('utf-8')
    admin_role = "admin"

    # Check if the admin user already exists
    if User.query.filter_by(email=admin_email).first():
        print("Admin user already exists!")
    else:
        admin_user = User(username=admin_username, email=admin_email, password=admin_password, role=admin_role)
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created successfully!")