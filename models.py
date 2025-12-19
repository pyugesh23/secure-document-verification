from datetime import datetime
from flask_login import UserMixin
from extensions import db


# =====================================================
# USER MODEL
# =====================================================

class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # admin | issuer | verifier
    fullname = db.Column(db.String(120))
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    documents = db.relationship("Document", backref="issuer", lazy=True)

    def __repr__(self):
        return f"<User {self.username}>"


# =====================================================
# DOCUMENT MODEL (ISSUER SIDE – PRIVATE)
# =====================================================

class Document(db.Model):
    __tablename__ = "documents"

    id = db.Column(db.Integer, primary_key=True)
    doc_id = db.Column(db.String(100), unique=True, nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    stored_path = db.Column(db.String(500), nullable=False)
    issued_path = db.Column(db.String(500), nullable=False)
    sha256 = db.Column(db.String(256), nullable=False)
    phash = db.Column(db.String(64))
    issuer_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    issued_at = db.Column(db.DateTime, default=datetime.utcnow)
    student_name = db.Column(db.String(120))
    remarks = db.Column(db.String(255))

    def __repr__(self):
        return f"<Document {self.doc_id}>"


# =====================================================
# PUBLIC LEDGER MODEL (CROSS-ORGANIZATION)
# This acts as a BLOCKCHAIN-LIKE hash registry
# =====================================================

class PublicLedger(db.Model):
    __tablename__ = "public_ledger"

    id = db.Column(db.Integer, primary_key=True)
    doc_id = db.Column(db.String(100), unique=True, nullable=False)
    doc_hash = db.Column(db.String(256), nullable=False)
    issuer = db.Column(db.String(120), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Ledger {self.doc_id}>"


# =====================================================
# AUDIT LOG MODEL
# =====================================================

class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    action = db.Column(db.String(50), nullable=False)
    doc_id = db.Column(db.String(100))
    details = db.Column(db.String(255))
    result = db.Column(db.String(20))  # VALID | FAKE | UNKNOWN | SUCCESS
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref="audit_logs")

    def __repr__(self):
        return f"<AuditLog {self.action} - {self.result}>"
