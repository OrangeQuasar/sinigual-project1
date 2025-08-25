import os
import json
import sqlite3
import mimetypes
import fitz  # PyMuPDF
import boto3
import re
import uuid
from dotenv import load_dotenv
from botocore.exceptions import ClientError
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer, SignatureExpired

# .envファイルから環境変数を読み込む
load_dotenv()

# .mjsファイル用のMIMEタイプをFlaskに教える
mimetypes.add_type('application/javascript', '.mjs')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_very_secret_key_change_me'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['THUMBNAIL_FOLDER'] = 'static/thumbnails'
ALLOWED_EXTENSIONS = {'pdf'}

# --- AWS SES設定 ---
AWS_REGION = os.environ.get('AWS_REGION')
SES_SENDER_EMAIL = os.environ.get('SES_SENDER_EMAIL')
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# --- データベース初期化 ---
def init_db():
    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                email_verified BOOLEAN NOT NULL DEFAULT FALSE
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

# --- メール送信関数 ---
def send_email(recipient, subject, body_html):
    if not (AWS_REGION and SES_SENDER_EMAIL):
        print("AWS設定が環境変数にありません。メールは送信されません。")
        return False
    
    client = boto3.client('ses', region_name=AWS_REGION)
    
    try:
        response = client.send_email(
            Destination={'ToAddresses': [recipient]},
            Message={
                'Body': {'Html': {'Charset': "UTF-8", 'Data': body_html}},
                'Subject': {'Charset': "UTF-8", 'Data': subject},
            },
            Source=SES_SENDER_EMAIL,
        )
    except ClientError as e:
        print(e.response['Error']['Message'])
        return False
    else:
        print(f"メール送信成功! Message ID: {response['MessageId']}")
        return True

# --- ヘルパー関数 ---
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_password_strong(password):
    if len(password) < 8:
        return False
    checks = [
        bool(re.search(r'[a-z]', password)),
        bool(re.search(r'[A-Z]', password)),
        bool(re.search(r'[0-9]', password)),
    ]
    return sum(checks) >= 2

# --- メインのルート ---
@app.route('/')
def home():
    conn = get_db_connection()
    logged_in_user_id = session.get('user_id')
    sql = """
        SELECT
            p.id, p.title, p.filename, p.thumbnail_filename, u.username,
            (SELECT '[' || IFNULL(GROUP_CONCAT(json_object('emoji', r.emoji, 'count', r.count)), '') || ']' FROM (SELECT emoji, COUNT(id) as count FROM reactions WHERE pdf_id = p.id GROUP BY emoji) as r) as reactions,
            (SELECT '[' || IFNULL(GROUP_CONCAT(json_quote(emoji)), '') || ']' FROM reactions WHERE pdf_id = p.id AND user_id = ?) as user_reactions
        FROM pdfs p JOIN users u ON p.user_id = u.id ORDER BY p.id DESC
    """
    pdfs_raw = conn.execute(sql, (logged_in_user_id,)).fetchall()
    conn.close()
    pdfs = [dict(row, reactions=json.loads(row['reactions']), user_reactions=json.loads(row['user_reactions'])) for row in pdfs_raw]
    return render_template('home.html', pdfs=pdfs)

@app.route('/account')
def account():
    if 'user_id' not in session:
        flash('このページにアクセスするにはログインが必要です。')
        return redirect(url_for('login'))
    conn = get_db_connection()
    user_pdfs = conn.execute('SELECT id, title FROM pdfs WHERE user_id = ? ORDER BY id DESC', (session['user_id'],)).fetchall()
    conn.close()
    return render_template('account.html', user_pdfs=user_pdfs)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session: return redirect(url_for('login'))
    file = request.files.get('file')
    title = request.form.get('title')
    if not file or not title:
        flash('タイトルとファイルを選択してください')
        return redirect(url_for('account'))
    if allowed_file(file.filename):
        file_extension = os.path.splitext(secure_filename(file.filename))[1]
        filename = f"{uuid.uuid4().hex}{file_extension}"
        pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(pdf_path)
        thumbnail_filename = f"thumb_{os.path.splitext(filename)[0]}.png"
        thumbnail_path = os.path.join(app.config['THUMBNAIL_FOLDER'], thumbnail_filename)
        try:
            with fitz.open(pdf_path) as doc:
                page = doc.load_page(0)
                pix = page.get_pixmap()
                pix.save(thumbnail_path)
        except Exception as e:
            print(f"サムネイル生成に失敗: {e}")
            thumbnail_filename = None
        conn = get_db_connection()
        conn.execute('INSERT INTO pdfs (title, filename, thumbnail_filename, user_id) VALUES (?, ?, ?, ?)',
                     (title, filename, thumbnail_filename, session['user_id']))
        conn.commit()
        conn.close()
        flash('PDFがアップロードされました！')
    else:
        flash('許可されていないファイル形式です')
    return redirect(url_for('account'))

@app.route('/react/<int:pdf_id>', methods=['POST'])
def react(pdf_id):
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'ログインが必要です'}), 401
    emoji = request.get_json().get('emoji')
    if not emoji: return jsonify({'success': False, 'error': '絵文字がありません'}), 400
    user_id = session['user_id']
    conn = get_db_connection()
    existing = conn.execute('SELECT id FROM reactions WHERE user_id = ? AND pdf_id = ? AND emoji = ?', (user_id, pdf_id, emoji)).fetchone()
    if existing:
        conn.execute('DELETE FROM reactions WHERE id = ?', (existing['id'],))
        action = 'removed'
    else:
        conn.execute('INSERT INTO reactions (user_id, pdf_id, emoji) VALUES (?, ?, ?)', (user_id, pdf_id, emoji))
        action = 'added'
    conn.commit()
    count = conn.execute('SELECT COUNT(id) as count FROM reactions WHERE pdf_id = ? AND emoji = ?', (pdf_id, emoji)).fetchone()['count']
    conn.close()
    return jsonify({'success': True, 'action': action, 'emoji': emoji, 'count': count})

# --- ユーザー認証とパスワードリセット ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username, email, password, password_confirm, terms = (request.form.get(k) for k in ['username', 'email', 'password', 'password_confirm', 'terms'])
        if not all([username, email, password, password_confirm]):
            flash('すべてのフィールドを入力してください。'); return render_template('register.html')
        if not terms:
            flash('利用規約に同意する必要があります。'); return render_template('register.html')
        if password != password_confirm:
            flash('パスワードが一致しません。'); return render_template('register.html')
        if not is_password_strong(password):
            flash('パスワードは8文字以上で、英字の大文字、小文字、数字のうち2種類以上を含めてください。'); return render_template('register.html')
        conn = get_db_connection()
        if conn.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email)).fetchone():
            flash('そのユーザー名またはメールアドレスは既に使用されています。'); conn.close(); return render_template('register.html')
        conn.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', (username, email, generate_password_hash(password)))
        conn.commit()
        conn.close()
        token = s.dumps(email, salt='email-confirm')
        confirm_url = url_for('confirm_email', token=token, _external=True)
        send_email(email, "アカウントの有効化をお願いします", render_template('email/activate.html', confirm_url=confirm_url))
        flash('確認メールを送信しました。メールボックスを確認してアカウントを有効化してください。')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
        conn = get_db_connection()
        conn.execute('UPDATE users SET email_verified = TRUE WHERE email = ?', (email,))
        conn.commit()
        conn.close()
        flash('メールアドレスが確認されました。ログインしてください。')
    except SignatureExpired:
        flash('確認リンクの有効期限が切れています。')
    except Exception:
        flash('無効な確認リンクです。')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username, password = request.form.get('username'), request.form.get('password')
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user and user['email_verified'] and check_password_hash(user['password'], password):
            session['user_id'], session['username'] = user['id'], user['username']
            send_email(user['email'], "【重要】ログイン通知", render_template('email/login_alert.html', username=user['username']))
            return redirect(url_for('account'))
        flash('ユーザー名、パスワードが正しくないか、アカウントが有効化されていません。')
    return render_template('login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        conn = get_db_connection()
        user = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        if user:
            token = s.dumps(email, salt='password-reset')
            reset_url = url_for('reset_password', token=token, _external=True)
            send_email(email, "パスワードのリセット", render_template('email/reset_password.html', reset_url=reset_url))
        flash('パスワードリセット用のメールを送信しました。メールアドレスが存在しない場合、メールは送信されません。')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=3600)
    except Exception:
        flash('パスワードリセットのリンクが無効か、有効期限が切れています。')
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        password, password_confirm = request.form.get('password'), request.form.get('password_confirm')
        if not all([password, password_confirm]):
            flash('新しいパスワードを入力してください。'); return render_template('reset_password.html', token=token)
        if password != password_confirm:
            flash('パスワードが一致しません。'); return render_template('reset_password.html', token=token)
        if not is_password_strong(password):
            flash('パスワードは8文字以上で、英字の大文字、小文字、数字のうち2種類以上を含めてください。'); return render_template('reset_password.html', token=token)
        conn = get_db_connection()
        conn.execute('UPDATE users SET password = ? WHERE email = ?', (generate_password_hash(password), email))
        conn.commit()
        conn.close()
        flash('パスワードが更新されました。新しいパスワードでログインしてください。')
        return redirect(url_for('login'))
    return render_template('reset_password.html', token=token)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- 実行ブロック ---
if __name__ == '__main__':
    for folder in [app.config['UPLOAD_FOLDER'], app.config['THUMBNAIL_FOLDER']]:
        if not os.path.exists(folder): os.makedirs(folder)
    if not os.path.exists('database.db'): init_db()
    app.run(debug=True)