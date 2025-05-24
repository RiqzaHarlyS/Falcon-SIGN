from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory
import os
import time
import hashlib
import uuid
import sys
import json
from PIL import Image
from io import BytesIO
import base64

# Tambahkan path ke folder falcon.py
sys.path.append('D:/Tugas/uas/falcon')
import falcon

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Maksimum 16MB

# Buat folder uploads jika belum ada
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'signatures'), exist_ok=True)

# Dictionary untuk menyimpan key pair sementara
# Catatan: Dalam produksi sebaiknya menggunakan penyimpanan yang lebih aman
keys_store = {}

def allowed_file(filename):
    """Cek apakah ekstensi file diizinkan"""
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'txt'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def file_to_bytes(file_path):
    """Membaca file dan mengembalikan sebagai bytes"""
    with open(file_path, 'rb') as f:
        return f.read()

def sign_file(file_path, secret_key, max_retries=10):
    """
    Menandatangani file menggunakan algoritma Falcon
    """
    file_bytes = file_to_bytes(file_path)
    retry_count = 0
    
    while retry_count < max_retries:
        try:
            signature = secret_key.sign(file_bytes)
            return signature, None
        except ValueError as e:
            if "Squared norm of signature is too large" in str(e):
                retry_count += 1
                if retry_count >= max_retries:
                    return None, str(e)
            else:
                return None, str(e)
    
    return None, "Gagal membuat tanda tangan setelah beberapa percobaan"

def verify_file(file_path, signature, public_key):
    """
    Verifikasi tanda tangan dari file menggunakan algoritma Falcon
    """
    file_bytes = file_to_bytes(file_path)
    try:
        return public_key.verify(file_bytes, signature), None
    except Exception as e:
        return False, str(e)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate-keys', methods=['POST'])
def generate_keys():
    try:
        # Parameter keamanan (nilai yang direkomendasikan: 512, 1024)
        n = int(request.form.get('security_param', '512'))
        if n not in [512, 1024]:
            n = 512  # Default ke 512 jika parameter tidak valid
        
        # Generate kunci rahasia dan kunci publik
        secret_key = falcon.SecretKey(n)
        public_key = falcon.PublicKey(secret_key)
        
        # Buat ID unik untuk pasangan kunci
        key_id = str(uuid.uuid4())
        keys_store[key_id] = {
            'secret_key': secret_key,
            'public_key': public_key,
            'created_at': time.time(),
            'n': n
        }
        
        # Hapus kunci yang sudah lama dibuat (lebih dari 1 jam)
        current_time = time.time()
        expired_keys = [k for k, v in keys_store.items() if current_time - v['created_at'] > 3600]
        for k in expired_keys:
            del keys_store[k]
        
        return jsonify({'status': 'success', 'key_id': key_id, 'n': n})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/sign', methods=['POST'])
def sign():
    if 'file' not in request.files:
        flash('Tidak ada file yang dipilih')
        return redirect(request.url)
    
    file = request.files['file']
    key_id = request.form.get('key_id')
    
    if file.filename == '':
        flash('Tidak ada file yang dipilih')
        return redirect(request.url)
    
    if key_id not in keys_store:
        flash('Kunci tidak ditemukan atau sudah kadaluarsa')
        return redirect(request.url)
    
    if file and allowed_file(file.filename):
        # Simpan file
        filename = str(uuid.uuid4()) + '_' + file.filename
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Tandatangani file
        secret_key = keys_store[key_id]['secret_key']
        signature, error = sign_file(file_path, secret_key)
        
        if signature:
            # Simpan signature ke file
            signature_filename = filename + '.sig'
            signature_path = os.path.join(app.config['UPLOAD_FOLDER'], 'signatures', signature_filename)
            with open(signature_path, 'wb') as f:
                f.write(signature)
            
            # Buat info hasil penandatanganan
            file_size = os.path.getsize(file_path)
            signature_size = len(signature)
            file_hash = hashlib.sha256(file_to_bytes(file_path)).hexdigest()
            
            # Untuk gambar, siapkan preview
            preview_data = None
            if file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
                img = Image.open(file_path)
                img.thumbnail((400, 400))
                buffered = BytesIO()
                img.save(buffered, format="PNG")
                preview_data = base64.b64encode(buffered.getvalue()).decode('utf-8')
            
            result = {
                'status': 'success',
                'filename': filename,
                'signature_filename': signature_filename,
                'file_size': file_size,
                'signature_size': signature_size,
                'file_hash': file_hash,
                'preview_data': preview_data,
                'file_type': file.filename.rsplit('.', 1)[1].lower()
            }
            
            return render_template('result.html', result=result)
        else:
            os.remove(file_path)  # Hapus file jika gagal
            flash(f'Gagal menandatangani file: {error}')
            return redirect(url_for('index'))
    
    flash('Tipe file tidak diizinkan')
    return redirect(url_for('index'))

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'GET':
        return render_template('verify.html')
    
    if 'file' not in request.files or 'signature' not in request.files:
        flash('File dan tanda tangan diperlukan')
        return redirect(request.url)
    
    file = request.files['file']
    signature_file = request.files['signature']
    key_id = request.form.get('key_id')
    
    if file.filename == '' or signature_file.filename == '':
        flash('File dan tanda tangan diperlukan')
        return redirect(request.url)
    
    if key_id not in keys_store:
        flash('Kunci tidak ditemukan atau sudah kadaluarsa')
        return redirect(request.url)
    
    if file and allowed_file(file.filename):
        # Simpan file dan tanda tangan
        filename = str(uuid.uuid4()) + '_' + file.filename
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        signature_filename = filename + '.sig'
        signature_path = os.path.join(app.config['UPLOAD_FOLDER'], 'signatures', signature_filename)
        signature_file.save(signature_path)
        
        # Baca tanda tangan
        with open(signature_path, 'rb') as f:
            signature = f.read()
        
        # Verifikasi file
        public_key = keys_store[key_id]['public_key']
        is_valid, error = verify_file(file_path, signature, public_key)
        
        # Buat info hasil verifikasi
        file_size = os.path.getsize(file_path)
        signature_size = os.path.getsize(signature_path)
        file_hash = hashlib.sha256(file_to_bytes(file_path)).hexdigest()
        
        # Untuk gambar, siapkan preview
        preview_data = None
        if file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
            img = Image.open(file_path)
            img.thumbnail((400, 400))
            buffered = BytesIO()
            img.save(buffered, format="PNG")
            preview_data = base64.b64encode(buffered.getvalue()).decode('utf-8')
        
        result = {
            'status': 'success',
            'is_valid': is_valid,
            'error': error,
            'filename': filename,
            'file_size': file_size,
            'signature_size': signature_size,
            'file_hash': file_hash,
            'preview_data': preview_data,
            'file_type': file.filename.rsplit('.', 1)[1].lower()
        }
        
        return render_template('verify_result.html', result=result)
    
    flash('Tipe file tidak diizinkan')
    return redirect(url_for('verify'))

@app.route('/download/<path:filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/download/signature/<path:filename>')
def download_signature(filename):
    return send_from_directory(os.path.join(app.config['UPLOAD_FOLDER'], 'signatures'), filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)