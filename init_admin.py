from werkzeug.security import generate_password_hash
from datetime import datetime

from app import app
from extensions import db
from models import User

# -------------------------
# Admin Credentials
# -------------------------
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"
ADMIN_ROLE = "admin"
ADMIN_FULLNAME = "System Administrator"

# -------------------------
# Initialize Database
# -------------------------
with app.app_context():
    print("Creating database tables...")
    db.create_all()

    admin = User.query.filter_by(username=ADMIN_USERNAME).first()

    if admin:
        print("Admin user already exists.")
    else:
        admin = User(
            username=ADMIN_USERNAME,
            password_hash=generate_password_hash(ADMIN_PASSWORD),
            role=ADMIN_ROLE,
            fullname=ADMIN_FULLNAME,
            active=True,
            created_at=datetime.utcnow()
        )
        db.session.add(admin)
        db.session.commit()

        print("Admin user created successfully!")
        print(f"Username: {ADMIN_USERNAME}")
        print(f"Password: {ADMIN_PASSWORD}")
