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


# =====================================================
# HELPERS
# =====================================================

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# =====================================================
# LOGIN
# =====================================================

@auth_bp.route("/", methods=["GET", "POST"])
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()

        if not user or not user.active:
            flash("Invalid login or inactive account", "danger")
            return redirect(url_for("auth.login"))

        if not check_password_hash(user.password_hash, password):
            flash("Invalid login or inactive account", "danger")
            return redirect(url_for("auth.login"))

        user.last_login = datetime.utcnow()
        db.session.commit()

        login_user(user)

        db.session.add(
            AuditLog(
                user_id=user.id,
                action="LOGIN",
                details="User logged in",
                result="SUCCESS"
            )
        )
        db.session.commit()

        return redirect(url_for("auth.dashboard"))

    return render_template("login.html")


# =====================================================
# DASHBOARD
# =====================================================

@auth_bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user)


# =====================================================
# LOGOUT
# =====================================================

@auth_bp.route("/logout")
@login_required
def logout():
    db.session.add(
        AuditLog(
            user_id=current_user.id,
            action="LOGOUT",
            details="User logged out",
            result="SUCCESS"
        )
    )
    db.session.commit()

    logout_user()
    return redirect(url_for("auth.login"))


# =====================================================
# ISSUE DOCUMENT  (CROSS-ORG ENABLED)
# =====================================================

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
            flash("Invalid file type", "danger")
            return redirect(url_for("auth.issue_document"))

        filename = secure_filename(file.filename)

        originals_dir = os.path.join(current_app.root_path, "storage", "originals")
        issued_dir = os.path.join(current_app.root_path, "storage", "issued")

        os.makedirs(originals_dir, exist_ok=True)
        os.makedirs(issued_dir, exist_ok=True)

        original_path = os.path.join(originals_dir, filename)
        file.save(original_path)

        # Generate unique document ID
        doc_id = f"DOC{int(datetime.utcnow().timestamp())}"

        # Temporary hash (before stamping)
        temp_hash = compute_sha256(original_path)

        qr_payload = (
            f"DOC:{doc_id}|"
            f"HASH:{temp_hash}|"
            f"TS:{datetime.utcnow().isoformat()}"
        )

        qr_img = generate_qr(qr_payload)

        issued_filename = f"ISSUED_{filename}"
        issued_path = os.path.join(issued_dir, issued_filename)

        # Stamp QR on document
        if filename.lower().endswith(".pdf"):
            stamp_qr_on_pdf(original_path, qr_img, issued_path)
        else:
            stamp_qr_on_image(original_path, qr_img, issued_path)

        # Final hashes
        final_sha = compute_sha256(issued_path)
        final_phash = compute_phash(issued_path)

        # Save issuer-side record
        doc = Document(
            doc_id=doc_id,
            filename=filename,
            stored_path=original_path,
            issued_path=issued_path,
            sha256=final_sha,
            phash=final_phash,
            issuer_id=current_user.id,
            student_name=student_name,
            issued_at=datetime.utcnow()
        )
        db.session.add(doc)

        # -------------------------------------------------
        # PUBLIC LEDGER (CROSS-ORG VERIFICATION)
        # -------------------------------------------------
        ledger_entry = PublicLedger(
            doc_id=doc_id,
            doc_hash=final_sha,
            issuer=current_user.username
        )
        db.session.add(ledger_entry)

        # Audit
        db.session.add(
            AuditLog(
                user_id=current_user.id,
                action="ISSUE_DOCUMENT",
                doc_id=doc_id,
                details="Document issued and published to public ledger",
                result="REGISTERED"
            )
        )

        db.session.commit()

        flash("Document issued successfully", "success")
        return redirect(url_for("auth.download_document", doc_id=doc_id))

    return render_template("issue.html")


# =====================================================
# VERIFY DOCUMENT  (CROSS-ORG)
# =====================================================

@auth_bp.route("/verify", methods=["GET", "POST"])
@login_required
def verify_document():
    result = None
    message = None

    if request.method == "POST":
        doc_file = request.files.get("document")

        if not doc_file:
            flash("Document file is required", "danger")
            return redirect(url_for("auth.verify_document"))

        verify_dir = os.path.join(current_app.root_path, "storage", "verify")
        os.makedirs(verify_dir, exist_ok=True)

        path = os.path.join(verify_dir, secure_filename(doc_file.filename))
        doc_file.save(path)

        computed_sha = compute_sha256(path)

        # ---------------------------------------------
        # STEP 1: TRY QR-BASED VERIFICATION
        # ---------------------------------------------
        qr_data = decode_qr(path)

        if qr_data and "HASH:" in qr_data:
            qr_hash = qr_data.split("HASH:")[1].split("|")[0]

            if qr_hash != computed_sha:
                result = "FAKE"
                message = "QR hash does not match document content"

            else:
                # -----------------------------------------
                # STEP 2: CHECK PUBLIC LEDGER
                # -----------------------------------------
                ledger = PublicLedger.query.filter_by(doc_hash=computed_sha).first()

                if ledger:
                    result = "VALID"
                    message = f"Verified successfully. Issued by {ledger.issuer}"
                else:
                    result = "FAKE"
                    message = "Hash not found in public ledger"

        else:
            # -----------------------------------------
            # FALLBACK: PHASH (SCANNED / PHOTO)
            # -----------------------------------------
            uploaded_phash = compute_phash(path)
            matched = False

            for doc in Document.query.all():
                if hamming_distance(uploaded_phash, doc.phash) <= PHASH_THRESHOLD:
                    ledger = PublicLedger.query.filter_by(doc_hash=doc.sha256).first()
                    if ledger:
                        result = "VALID"
                        message = f"Verified via scan. Issued by {ledger.issuer}"
                        matched = True
                        break

            if not matched:
                result = "UNKNOWN"
                message = "No matching record found"

        # ---------------------------------------------
        # AUDIT LOG
        # ---------------------------------------------
        db.session.add(
            AuditLog(
                user_id=current_user.id,
                action="VERIFY_DOCUMENT",
                details=message,
                result=result
            )
        )
        db.session.commit()

    return render_template("verify.html", result=result, message=message)


# =====================================================
# DOWNLOAD ISSUED DOCUMENT
# =====================================================

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


# =====================================================
# ADMIN PANEL
# =====================================================

@auth_bp.route("/admin")
@login_required
def admin_panel():
    if current_user.role != "admin":
        flash("Unauthorized access", "danger")
        return redirect(url_for("auth.dashboard"))

    users = User.query.all()
    documents = Document.query.all()
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()
    ledger = PublicLedger.query.all()

    return render_template(
        "admin.html",
        users=users,
        documents=documents,
        logs=logs,
        ledger=ledger
    )


# =====================================================
# ADMIN CLEAR DATABASE RECORDS ONLY
# =====================================================

@auth_bp.route("/admin/clear", methods=["POST"])
@login_required
def clear_all_data():
    if current_user.role != "admin":
        flash("Unauthorized action", "danger")
        return redirect(url_for("auth.dashboard"))

    Document.query.delete()
    AuditLog.query.delete()
    PublicLedger.query.delete()
    db.session.commit()

    flash("All document records and ledger entries cleared", "success")
    return redirect(url_for("auth.admin_panel"))
