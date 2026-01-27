import os
from datetime import datetime

from flask import (
    Blueprint, render_template, request,
    redirect, url_for, flash, current_app, send_file
)
from flask_login import (
    login_user, logout_user, login_required, current_user
)
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename

from extensions import db
from models import User, Document, AuditLog, PublicLedger
from utils import (
    generate_qr,
    compute_sha256,
    compute_phash,
    stamp_qr_on_pdf,
    stamp_qr_on_image,
    decode_qr,
    hamming_distance
)

auth_bp = Blueprint("auth", __name__)

ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg"}
PHASH_THRESHOLD = 8


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# -------------------------------------------------
# LOGIN
# -------------------------------------------------
@auth_bp.route("/", methods=["GET", "POST"])
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(
            username=request.form.get("username")
        ).first()

        if not user or not user.active or not check_password_hash(
            user.password_hash, request.form.get("password")
        ):
            flash("Invalid login or inactive account", "danger")
            return redirect(url_for("auth.login"))

        user.last_login = datetime.utcnow()
        db.session.commit()

        login_user(user)
        return redirect(url_for("auth.dashboard"))

    return render_template("login.html")


# -------------------------------------------------
# DASHBOARD
# -------------------------------------------------
@auth_bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user)


# -------------------------------------------------
# LOGOUT
# -------------------------------------------------
@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))


# -------------------------------------------------
# ISSUE DOCUMENT (ADMIN / ISSUER)
# -------------------------------------------------
@auth_bp.route("/issue", methods=["GET", "POST"])
@login_required
def issue_document():

    if current_user.role not in ["admin", "issuer"]:
        flash("Unauthorized access", "danger")
        return redirect(url_for("auth.dashboard"))

    if request.method == "POST":
        file = request.files.get("document")
        student_name = request.form.get("student_name")

        if not file or not allowed_file(file.filename):
            flash("Invalid file", "danger")
            return redirect(url_for("auth.issue_document"))

        filename = secure_filename(file.filename)

        originals_dir = os.path.join(current_app.root_path, "storage", "originals")
        issued_dir = os.path.join(current_app.root_path, "storage", "issued")
        os.makedirs(originals_dir, exist_ok=True)
        os.makedirs(issued_dir, exist_ok=True)

        original_path = os.path.join(originals_dir, filename)
        file.save(original_path)

        doc_id = f"DOC{int(datetime.utcnow().timestamp())}"

        # ---- Stamp QR (DOC ID only) ----
        qr_img = generate_qr(f"DOC:{doc_id}")
        issued_path = os.path.join(issued_dir, f"ISSUED_{filename}")

        if filename.lower().endswith(".pdf"):
            stamp_qr_on_pdf(original_path, qr_img, issued_path)
        else:
            stamp_qr_on_image(original_path, qr_img, issued_path)

        # ---- Final hashes (AFTER stamping) ----
        final_sha = compute_sha256(issued_path)
        final_phash = compute_phash(issued_path)

        # ---- Store in DB ----
        db.session.add(Document(
            doc_id=doc_id,
            filename=filename,
            stored_path=original_path,
            issued_path=issued_path,
            sha256=final_sha,
            phash=final_phash,
            issuer_id=current_user.id,
            student_name=student_name
        ))

        db.session.add(PublicLedger(
            doc_id=doc_id,
            doc_hash=final_sha,
            issuer=current_user.username
        ))

        db.session.add(AuditLog(
            user_id=current_user.id,
            action="ISSUE_DOCUMENT",
            doc_id=doc_id,
            result="SUCCESS"
        ))

        db.session.commit()

        flash("Document issued successfully", "success")
        return redirect(url_for("auth.download_document", doc_id=doc_id))

    return render_template("issue.html")


# -------------------------------------------------
# VERIFY DOCUMENT (ADMIN / VERIFIER)
# -------------------------------------------------
@auth_bp.route("/verify", methods=["GET", "POST"])
@login_required
def verify_document():

    if current_user.role not in ["admin", "verifier"]:
        flash("Unauthorized access", "danger")
        return redirect(url_for("auth.dashboard"))

    result = None
    message = None

    if request.method == "POST":
        file = request.files.get("document")

        if not file:
            flash("Document required", "danger")
            return redirect(url_for("auth.verify_document"))

        verify_dir = os.path.join(current_app.root_path, "storage", "verify")
        os.makedirs(verify_dir, exist_ok=True)

        path = os.path.join(verify_dir, secure_filename(file.filename))
        file.save(path)

        verified = False

        # -------- 1️⃣ QR BASED VERIFICATION (PRIMARY) --------
        qr_data = decode_qr(path)

        if qr_data and qr_data.startswith("DOC:"):
            doc_id = qr_data.replace("DOC:", "").strip()

            uploaded_hash = compute_sha256(path)
            ledger_entry = PublicLedger.query.filter_by(doc_id=doc_id).first()

            if ledger_entry:
                if uploaded_hash == ledger_entry.doc_hash:
                    result = "VALID"
                    message = "Document verified successfully (hash matched)"
                else:
                    result = "FAKE"
                    message = "Document tampered (hash mismatch)"
                verified = True
            else:
                result = "FAKE"
                message = "QR found but document not registered"
                verified = True

        # -------- 2️⃣ VISUAL MATCH (SCAN / PHOTO) --------
        if not verified:
            uploaded_phash = compute_phash(path)
            for doc in Document.query.all():
                if hamming_distance(uploaded_phash, doc.phash) <= PHASH_THRESHOLD:
                    result = "UNKNOWN"
                    message = "Visually similar document detected (scan/photo)"
                    verified = True
                    break

        # -------- 3️⃣ FINAL FALLBACK --------
        if not verified:
            result = "FAKE"
            message = "Unrecognized or forged document"

        db.session.add(AuditLog(
            user_id=current_user.id,
            action="VERIFY_DOCUMENT",
            result=result
        ))
        db.session.commit()

    return render_template("verify.html", result=result, message=message)


# -------------------------------------------------
# ADMIN PANEL
# -------------------------------------------------
@auth_bp.route("/admin")
@login_required
def admin_panel():

    if current_user.role != "admin":
        flash("Unauthorized access", "danger")
        return redirect(url_for("auth.dashboard"))

    return render_template(
        "admin.html",
        users=User.query.all(),
        documents=Document.query.all(),
        ledger=PublicLedger.query.all(),
        logs=AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()
    )


# -------------------------------------------------
# DOWNLOAD
# -------------------------------------------------
@auth_bp.route("/download/<doc_id>")
@login_required
def download_document(doc_id):

    doc = Document.query.filter_by(doc_id=doc_id).first()

    if not doc:
        flash("Document not found", "danger")
        return redirect(url_for("auth.dashboard"))

    return send_file(
        doc.issued_path,
        as_attachment=True,
        download_name=os.path.basename(doc.issued_path)
    )
