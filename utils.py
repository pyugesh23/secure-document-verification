import os
import io
import hashlib

import qrcode
import cv2
import numpy as np
import imagehash
from PIL import Image

import fitz  # PyMuPDF


# ======================================================
# HASHING UTILITIES
# ======================================================

def compute_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


# ======================================================
# QR CODE GENERATION & DECODING
# ======================================================

def generate_qr(data):
    qr = qrcode.QRCode(
        version=2,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=8,
        border=2
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    return img.convert("RGB")


def decode_qr(file_path):
    """
    Decode QR from image OR first page of PDF
    """
    detector = cv2.QRCodeDetector()

    # IMAGE
    if file_path.lower().endswith((".jpg", ".jpeg", ".png")):
        img = cv2.imread(file_path)
        if img is None:
            return None
        data, _, _ = detector.detectAndDecode(img)
        return data if data else None

    # PDF
    if file_path.lower().endswith(".pdf"):
        try:
            doc = fitz.open(file_path)
            page = doc.load_page(0)
            pix = page.get_pixmap(matrix=fitz.Matrix(2, 2))
            img = np.frombuffer(pix.samples, dtype=np.uint8).reshape(
                pix.height, pix.width, pix.n
            )

            if pix.n == 4:
                img = cv2.cvtColor(img, cv2.COLOR_BGRA2BGR)

            data, _, _ = detector.detectAndDecode(img)
            doc.close()
            return data if data else None
        except Exception:
            return None

    return None


# ======================================================
# PDF → IMAGE (for pHash)
# ======================================================

def pdf_page_to_image(pdf_path):
    doc = fitz.open(pdf_path)
    page = doc.load_page(0)
    pix = page.get_pixmap(matrix=fitz.Matrix(2, 2))
    img = Image.open(io.BytesIO(pix.tobytes("png"))).convert("RGB")
    doc.close()
    return img


# ======================================================
# PERCEPTUAL HASH (pHash)
# ======================================================

def compute_phash(file_path):
    if file_path.lower().endswith(".pdf"):
        img = pdf_page_to_image(file_path)
    else:
        img = Image.open(file_path).convert("RGB")
    return str(imagehash.phash(img))


def hamming_distance(hash1, hash2):
    return imagehash.hex_to_hash(hash1) - imagehash.hex_to_hash(hash2)


# ======================================================
# QR STAMPING — PDF (FOOTER CENTER)
# ======================================================

def stamp_qr_on_pdf(pdf_path, qr_img, output_path):
    doc = fitz.open(pdf_path)
    page = doc.load_page(0)

    original_rect = page.rect
    footer_height = 60

    new_page = doc.new_page(
        width=original_rect.width,
        height=original_rect.height + footer_height
    )

    new_page.show_pdf_page(
        fitz.Rect(0, 0, original_rect.width, original_rect.height),
        doc,
        0
    )

    footer_rect = fitz.Rect(
        0,
        original_rect.height,
        original_rect.width,
        original_rect.height + footer_height
    )

    new_page.draw_rect(footer_rect, fill=(1, 1, 1))

    qr_size = 40
    qr_bytes = io.BytesIO()
    qr_img.resize((qr_size, qr_size)).save(qr_bytes, format="PNG")
    qr_bytes.seek(0)

    qr_x = (original_rect.width / 2) - (qr_size / 2)
    qr_y = original_rect.height + 10

    qr_rect = fitz.Rect(
        qr_x,
        qr_y,
        qr_x + qr_size,
        qr_y + qr_size
    )

    new_page.insert_image(qr_rect, stream=qr_bytes.read())

    new_page.insert_text(
        (20, original_rect.height + 55),
        "Digitally Verified Certificate – Scan QR to verify",
        fontsize=9
    )

    doc.delete_page(0)
    doc.save(output_path, garbage=4, deflate=True, clean=True)
    doc.close()


# ======================================================
# QR STAMPING — IMAGE (FOOTER CENTER)
# ======================================================

def stamp_qr_on_image(image_path, qr_img, output_path):
    img = Image.open(image_path).convert("RGB")
    w, h = img.size

    footer_height = 50
    qr_size = min(40, w // 8)

    new_img = Image.new("RGB", (w, h + footer_height), (255, 255, 255))
    new_img.paste(img, (0, 0))

    qr_img = qr_img.resize((qr_size, qr_size))

    qr_x = (w // 2) - (qr_size // 2)
    qr_y = h + (footer_height // 2) - (qr_size // 2)

    new_img.paste(qr_img, (qr_x, qr_y))
    new_img.save(output_path)
