import os
import json
import sqlite3
import mimetypes
import fitz  # PyMuPDF
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# .mjsファイル用のMIMEタイプをFlaskに教える
mimetypes.add_type('application/javascript', '.mjs')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_very_secret_key_change_me'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['THUMBNAIL_FOLDER'] = 'static/thumbnails'
ALLOWED_EXTENSIONS = {'pdf'}

# --- データベース初期化 (変更なし) ---
def init_db():
    # ... (この関数の中身は変更ありません) ...
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
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                pdf_id INTEGER NOT NULL,
                emoji TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (pdf_id) REFERENCES pdfs (id),
                UNIQUE(user_id, pdf_id, emoji)
            )
        ''')
        conn.commit()


# --- ヘルパー関数 (変更なし) ---
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- ルート ---

@app.route('/')
def home():
    
    conn = get_db_connection()
    # ... (以降のhome関数の処理は変更ありません) ...
    logged_in_user_id = session.get('user_id')
    sql = """
        SELECT
            p.id, p.title, p.filename, p.thumbnail_filename, u.username,
            (
                SELECT
                    '[' || IFNULL(GROUP_CONCAT(json_object('emoji', r.emoji, 'count', r.count)), '') || ']'
                FROM (
                    SELECT emoji, COUNT(id) as count
                    FROM reactions
                    WHERE pdf_id = p.id
                    GROUP BY emoji
                ) as r
            ) as reactions,
            (
                SELECT
                    '[' || IFNULL(GROUP_CONCAT(json_quote(emoji)), '') || ']'
                FROM reactions
                WHERE pdf_id = p.id AND user_id = ?
            ) as user_reactions
        FROM
            pdfs p
        JOIN
            users u ON p.user_id = u.id
        ORDER BY
            p.id DESC
    """
    pdfs_raw = conn.execute(sql, (logged_in_user_id,)).fetchall()
    conn.close()
    pdfs = []
    for row in pdfs_raw:
        pdf = dict(row)
        pdf['reactions'] = json.loads(pdf['reactions'])
        pdf['user_reactions'] = json.loads(pdf['user_reactions'])
        pdfs.append(pdf)
    return render_template('home.html', pdfs=pdfs)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            return redirect(url_for('account'))
        else:
            flash('ユーザー名またはパスワードが正しくありません。')
            
    return render_template('login.html')

# (以降の関数 account, upload_file, react, register, logout などは変更ありません)
@app.route('/account')
def account():
    if 'user_id' not in session:
        flash('このページにアクセスするにはログインが必要です。')
        return redirect(url_for('login'))
    conn = get_db_connection()
    user_pdfs = conn.execute(
        'SELECT id, title, filename FROM pdfs WHERE user_id = ? ORDER BY id DESC',
        (session['user_id'],)
    ).fetchall()
    conn.close()
    return render_template('account.html', user_pdfs=user_pdfs)
@app.route('/upload', methods=['POST'])
def upload_file():
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
        thumbnail_filename = f"thumb_{os.path.splitext(filename)[0]}.png"
        thumbnail_path = os.path.join(app.config['THUMBNAIL_FOLDER'], thumbnail_filename)
        try:
            doc = fitz.open(pdf_path)
            page = doc.load_page(0)
            pix = page.get_pixmap()
            pix.save(thumbnail_path)
            doc.close()
        except Exception as e:
            print(f"サムネイル生成に失敗: {e}")
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
@app.route('/react/<int:pdf_id>', methods=['POST'])
def react(pdf_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'ログインが必要です'}), 401
    data = request.get_json()
    emoji = data.get('emoji')
    if not emoji:
        return jsonify({'success': False, 'error': '絵文字がありません'}), 400
    user_id = session['user_id']
    conn = get_db_connection()
    existing_reaction = conn.execute(
        'SELECT id FROM reactions WHERE user_id = ? AND pdf_id = ? AND emoji = ?',
        (user_id, pdf_id, emoji)
    ).fetchone()
    if existing_reaction:
        conn.execute('DELETE FROM reactions WHERE id = ?', (existing_reaction['id'],))
        action = 'removed'
    else:
        conn.execute(
            'INSERT INTO reactions (user_id, pdf_id, emoji) VALUES (?, ?, ?)',
            (user_id, pdf_id, emoji)
        )
        action = 'added'
    conn.commit()
    reaction_count = conn.execute(
        'SELECT COUNT(id) as count FROM reactions WHERE pdf_id = ? AND emoji = ?',
        (pdf_id, emoji)
    ).fetchone()['count']
    conn.close()
    return jsonify({
        'success': True,
        'action': action,
        'emoji': emoji,
        'count': reaction_count
    })
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_confirm = request.form['password_confirm']

        if password != password_confirm:
            flash('パスワードが一致しません。もう一度お試しください。')
            return redirect(url_for('register'))

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
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    if not os.path.exists(app.config['THUMBNAIL_FOLDER']):
        os.makedirs(app.config['THUMBNAIL_FOLDER'])
    if not os.path.exists('database.db'):
        init_db()
    app.run(debug=True)