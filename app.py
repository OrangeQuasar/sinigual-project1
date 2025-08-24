import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import mimetypes
import fitz  # PyMuPDF

# Teach Flask the correct MIME type for .mjs files
mimetypes.add_type('application/javascript', '.mjs')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_very_secret_key'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['THUMBNAIL_FOLDER'] = 'static/thumbnails'
ALLOWED_EXTENSIONS = {'pdf'}

# --- Database Initialization ---
def init_db():
    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pdfs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                filename TEXT NOT NULL,
                thumbnail_filename TEXT,
                user_id INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        conn.commit()

# --- Helper Functions (The missing functions) ---

def get_db_connection():
    """Establishes a connection to the database."""
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def allowed_file(filename):
    """Checks if the file extension is allowed."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Routes ---

@app.route('/')
def home():
    """Public home page, shows all PDFs."""
    conn = get_db_connection()
    pdfs = conn.execute('''
        SELECT pdfs.id, pdfs.title, pdfs.filename, pdfs.thumbnail_filename, users.username
        FROM pdfs
        JOIN users ON pdfs.user_id = users.id
        ORDER BY pdfs.id DESC
    ''').fetchall()
    conn.close()
    return render_template('home.html', pdfs=pdfs)

@app.route('/account')
def account():
    """User's account page for uploading and viewing their PDFs."""
    if 'user_id' not in session:
        flash('このページにアクセスするにはログインが必要です。')
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    user_pdfs = conn.execute('''
        SELECT id, title, filename FROM pdfs
        WHERE user_id = ?
        ORDER BY id DESC
    ''', (session['user_id'],)).fetchall()
    conn.close()
    return render_template('account.html', user_pdfs=user_pdfs)

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handles PDF file uploads and thumbnail generation."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if 'file' not in request.files or 'title' not in request.form or request.form['title'] == '':
        flash('タイトルとファイルを選択してください')
        return redirect(url_for('account'))
        
    file = request.files['file']
    title = request.form['title']
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(pdf_path)
        
        # Generate thumbnail
        thumbnail_filename = f"thumb_{os.path.splitext(filename)[0]}.png"
        thumbnail_path = os.path.join(app.config['THUMBNAIL_FOLDER'], thumbnail_filename)
        
        try:
            doc = fitz.open(pdf_path)
            page = doc.load_page(0)
            pix = page.get_pixmap()
            pix.save(thumbnail_path)
            doc.close()
        except Exception as e:
            print(f"Thumbnail generation failed: {e}")
            thumbnail_filename = None
        
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO pdfs (title, filename, thumbnail_filename, user_id) VALUES (?, ?, ?, ?)',
            (title, filename, thumbnail_filename, session['user_id'])
        )
        conn.commit()
        conn.close()
        
        flash('PDFがアップロードされました！')
        return redirect(url_for('account'))

    flash('許可されていないファイル形式、またはファイルが選択されていません')
    return redirect(url_for('account'))

# --- User Authentication Routes ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            flash('登録が完了しました。ログインしてください。')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('そのユーザー名は既に使用されています。')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('account'))
        else:
            flash('ユーザー名またはパスワードが正しくありません。')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Provides access to uploaded PDF files."""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- Main Execution Block ---

if __name__ == '__main__':
    # Create necessary folders if they don't exist
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    if not os.path.exists('static/thumbnails'):
        os.makedirs('static/thumbnails')
    
    # Initialize the database if it doesn't exist
    if not os.path.exists('database.db'):
        init_db()

    app.run(debug=True)