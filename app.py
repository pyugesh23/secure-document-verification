import os
from datetime import timedelta
from flask import Flask
from extensions import db, login_manager

# -------------------------
# App Setup
# -------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

app.config['SECRET_KEY'] = 'offline-doc-verifier-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# -------------------------
# Initialize Extensions
# -------------------------
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'auth.login'
login_manager.login_message = "Please login to continue"

# -------------------------
# Folder Initialization
# -------------------------
REQUIRED_FOLDERS = [
    'storage',
    'storage/originals',
    'storage/issued',
    'logs'
]

for folder in REQUIRED_FOLDERS:
    os.makedirs(os.path.join(BASE_DIR, folder), exist_ok=True)

# -------------------------
# Models & Blueprints
# -------------------------
from models import User
from auth import auth_bp

app.register_blueprint(auth_bp)

# -------------------------
# User Loader
# -------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -------------------------
# Main
# -------------------------
if __name__ == '__main__':
    app.run(debug=True)
