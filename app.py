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
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_fallback_secret_key_for_development')

# トークン生成用のシリアライザーを初期化
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# --- AWSクライアントの初期化 ---
# 環境変数が設定されているかチェック
AWS_CONFIGURED = all(os.environ.get(key) for key in ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_REGION', 'SES_SENDER_EMAIL'])

if AWS_CONFIGURED:
    ses_client = boto3.client('ses', region_name=os.environ.get('AWS_REGION'))
    s3_client = boto3.client('s3', region_name=os.environ.get('AWS_REGION'))
    SENDER_EMAIL = os.environ.get('SES_SENDER_EMAIL')
    S3_BUCKET_PDF = os.environ.get('S3_BUCKET_PDF')
    S3_BUCKET_THUMBNAILS = os.environ.get('S3_BUCKET_THUMBNAILS')
else:
    print("警告: AWS設定が環境変数にありません。メール送信とS3アップロードは無効になります。")
    ses_client = None
    s3_client = None

# --- グローバル変数として定義 ---
ALLOWED_EXTENSIONS = {'pdf'}

# --- ヘルパー関数 ---

def get_db_connection():
    """データベースへの接続を確立する (PostgreSQL/SQLite対応)"""
    db_url = os.environ.get('DATABASE_URL')
    if db_url and db_url.startswith('postgres'):
        # 本番環境: PostgreSQL
        import psycopg2
        from psycopg2.extras import DictCursor
        conn = psycopg2.connect(db_url)
        conn.cursor_factory = DictCursor
    else:
        # 開発環境: SQLite
        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
    return conn

def allowed_file(filename):
    """許可されたファイル拡張子かチェックする"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_password_strong(password):
    """パスワードの強度を検証する"""
    if len(password) < 8:
        return False, "パスワードは8文字以上である必要があります。"
    
    checks = {
        'lowercase': bool(re.search(r'[a-z]', password)),
        'uppercase': bool(re.search(r'[A-Z]', password)),
        'digit': bool(re.search(r'\d', password)),
    }
    
    if sum(checks.values()) < 2:
        return False, "パスワードには、アルファベット小文字、大文字、数字のうち2種類以上を含める必要があります。"
    
    return True, ""

def send_email(recipient, subject, template, **kwargs):
    """Amazon SESを使ってメールを送信する"""
    if not AWS_CONFIGURED or not ses_client:
        print(f"メール送信スキップ (AWS未設定): To={recipient}, Subject={subject}")
        return False
    
    body_html = render_template(template, **kwargs)
    
    try:
        response = ses_client.send_email(
            Source=SENDER_EMAIL,
            Destination={'ToAddresses': [recipient]},
            Message={
                'Subject': {'Data': subject, 'Charset': 'UTF-8'},
                'Body': {'Html': {'Data': body_html, 'Charset': 'UTF-8'}}
            }
        )
    except ClientError as e:
        print(f"メール送信エラー: {e.response['Error']['Message']}")
        return False
    else:
        print(f"メール送信成功: Message ID: {response['MessageId']}")
        return True

# --- データベース初期化 ---
def init_db():
    # PostgreSQLの場合は手動またはマイグレーションツールでテーブル作成を推奨
    # ここではSQLite用の初期化コードを残す
    conn = get_db_connection()
    if conn.__class__.__module__ == 'sqlite3':
        with conn:
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
    conn.close()

# --- ルート定義 ---

@app.route('/')
def home():
    """ホームページ。全てのPDFをリアクション付きで表示"""
    conn = get_db_connection()
    cursor = conn.cursor()
    logged_in_user_id = session.get('user_id')

    # SQLiteとPostgreSQLで文法が異なるため、条件分岐
    if conn.__class__.__module__ == 'sqlite3':
        sql = """
            SELECT
                p.id, p.title, p.filename, p.thumbnail_filename, u.username,
                (
                    SELECT '[' || GROUP_CONCAT(json_object('emoji', r.emoji, 'count', r.count)) || ']'
                    FROM (
                        SELECT emoji, COUNT(id) as count
                        FROM reactions
                        WHERE pdf_id = p.id
                        GROUP BY emoji
                    ) as r
                ) as reactions,
                (
                    SELECT '[' || GROUP_CONCAT(json_quote(emoji)) || ']'
                    FROM reactions
                    WHERE pdf_id = p.id AND user_id = ?
                ) as user_reactions
            FROM pdfs p
            JOIN users u ON p.user_id = u.id
            ORDER BY p.id DESC
        """
        cursor.execute(sql, (logged_in_user_id,))
    else: # PostgreSQL
        sql = """
            SELECT
                p.id, p.title, p.filename, p.thumbnail_filename, u.username,
                COALESCE(r.reactions, '[]'::json) as reactions,
                COALESCE(ur.user_reactions, '[]'::json) as user_reactions
            FROM pdfs p
            JOIN users u ON p.user_id = u.id
            LEFT JOIN (
                SELECT pdf_id, json_agg(json_build_object('emoji', emoji, 'count', count)) as reactions
                FROM (
                    SELECT pdf_id, emoji, count(*) as count FROM reactions GROUP BY pdf_id, emoji
                ) as counts
                GROUP BY pdf_id
            ) r ON p.id = r.pdf_id
            LEFT JOIN (
                SELECT pdf_id, json_agg(emoji) as user_reactions
                FROM reactions
                WHERE user_id = %s
                GROUP BY pdf_id
            ) ur ON p.id = ur.pdf_id
            ORDER BY p.id DESC
        """
        cursor.execute(sql, (logged_in_user_id,))
    
    pdfs_raw = cursor.fetchall()
    cursor.close()
    conn.close()

    # URLを付与して最終的なリストを作成
    pdfs = []
    for row in pdfs_raw:
        pdf = dict(row)
        
        # S3が設定されていればS3のURLを、なければローカルのURLを使用
        if S3_BUCKET_PDF and s3_client:
            aws_region = os.environ.get('AWS_REGION')
            s3_pdf_base_url = f"https://{S3_BUCKET_PDF}.s3.{aws_region}.amazonaws.com/"
            s3_thumb_base_url = f"https://{S3_BUCKET_THUMBNAILS}.s3.{aws_region}.amazonaws.com/"
            
            pdf['pdf_url'] = s3_pdf_base_url + pdf['filename']
            if pdf['thumbnail_filename']:
                pdf['thumbnail_url'] = s3_thumb_base_url + pdf['thumbnail_filename']
            else:
                pdf['thumbnail_url'] = url_for('static', filename='placeholder.png')
        else:
            # S3が未設定の場合 (開発環境)
            pdf['pdf_url'] = url_for('uploaded_file', filename=pdf['filename'])
            if pdf['thumbnail_filename']:
                pdf['thumbnail_url'] = url_for('static', filename=f"thumbnails/{pdf['thumbnail_filename']}")
            else:
                pdf['thumbnail_url'] = url_for('static', filename='placeholder.png')

        # SQLiteからのJSON文字列をパースする
        if isinstance(pdf.get('reactions'), str):
            pdf['reactions'] = json.loads(pdf['reactions']) if pdf['reactions'] else []
        if isinstance(pdf.get('user_reactions'), str):
            pdf['user_reactions'] = json.loads(pdf['user_reactions']) if pdf['user_reactions'] else []

        pdfs.append(pdf)
            
    return render_template('home.html', pdfs=pdfs)

@app.route('/account')
def account():
    if 'user_id' not in session:
        flash('このページにアクセスするにはログインが必要です。')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    # PostgreSQLとSQLiteでプレースホルダが異なる
    placeholder = '%s' if conn.__class__.__module__ != 'sqlite3' else '?'
    sql = f'SELECT id, title FROM pdfs WHERE user_id = {placeholder} ORDER BY id DESC'
    cursor.execute(sql, (session['user_id'],))
    user_pdfs = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return render_template('account.html', user_pdfs=user_pdfs)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    file = request.files.get('file')
    title = request.form.get('title')

    if not file or not title:
        flash('タイトルとファイルを選択してください')
        return redirect(url_for('account'))

    if allowed_file(file.filename):
        file_extension = os.path.splitext(secure_filename(file.filename))[1]
        filename_uuid = f"{uuid.uuid4().hex}{file_extension}"
        thumbnail_filename_uuid = f"thumb_{uuid.uuid4().hex}.png"

        try:
            # サムネイル生成
            with fitz.open(stream=file.read(), filetype="pdf") as doc:
                page = doc.load_page(0)
                pix = page.get_pixmap()
                thumbnail_bytes = pix.tobytes("png")

            # S3へアップロード
            if s3_client and S3_BUCKET_PDF and S3_BUCKET_THUMBNAILS:
                file.seek(0) # streamを先頭に戻す
                s3_client.upload_fileobj(file, S3_BUCKET_PDF, filename_uuid)
                s3_client.put_object(Body=thumbnail_bytes, Bucket=S3_BUCKET_THUMBNAILS, Key=thumbnail_filename_uuid, ContentType='image/png')
            else:
                # 開発用にローカルにも保存する場合
                local_pdf_path = os.path.join('uploads', filename_uuid)
                local_thumb_path = os.path.join('static/thumbnails', thumbnail_filename_uuid)
                file.seek(0)
                file.save(local_pdf_path)
                with open(local_thumb_path, "wb") as f:
                    f.write(thumbnail_bytes)

        except Exception as e:
            flash(f"ファイルの処理中にエラーが発生しました: {e}")
            return redirect(url_for('account'))

        # データベースに保存
        conn = get_db_connection()
        cursor = conn.cursor()
        placeholder = '%s' if conn.__class__.__module__ != 'sqlite3' else '?'
        sql = f'INSERT INTO pdfs (title, filename, thumbnail_filename, user_id) VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder})'
        cursor.execute(sql, (title, filename_uuid, thumbnail_filename_uuid, session['user_id']))
        conn.commit()
        cursor.close()
        conn.close()
        flash('PDFがアップロードされました！')
    else:
        flash('許可されていないファイル形式です')
        
    return redirect(url_for('account'))

@app.route('/react/<int:pdf_id>', methods=['POST'])
def react(pdf_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'ログインが必要です'}), 401
    
    emoji = request.get_json().get('emoji')
    if not emoji:
        return jsonify({'success': False, 'error': '絵文字がありません'}), 400
    
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    placeholder = '%s' if conn.__class__.__module__ != 'sqlite3' else '?'

    sql_select = f'SELECT id FROM reactions WHERE user_id = {placeholder} AND pdf_id = {placeholder} AND emoji = {placeholder}'
    cursor.execute(sql_select, (user_id, pdf_id, emoji))
    existing = cursor.fetchone()

    if existing:
        sql_delete = f'DELETE FROM reactions WHERE id = {placeholder}'
        cursor.execute(sql_delete, (existing['id'],))
        action = 'removed'
    else:
        sql_insert = f'INSERT INTO reactions (user_id, pdf_id, emoji) VALUES ({placeholder}, {placeholder}, {placeholder})'
        cursor.execute(sql_insert, (user_id, pdf_id, emoji))
        action = 'added'
    
    conn.commit()
    
    sql_count = f'SELECT COUNT(id) as count FROM reactions WHERE pdf_id = {placeholder} AND emoji = {placeholder}'
    cursor.execute(sql_count, (pdf_id, emoji))
    count = cursor.fetchone()['count']
    
    cursor.close()
    conn.close()
    
    return jsonify({'success': True, 'action': action, 'emoji': emoji, 'count': count})

# --- ユーザー認証とパスワードリセットのルート ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        password_confirm = request.form.get('password_confirm')
        terms = request.form.get('terms')

        if not all([username, email, password, password_confirm]):
            flash('すべてのフィールドを入力してください。')
            return render_template('register.html')
        if not terms:
            flash('利用規約に同意する必要があります。')
            return render_template('register.html')
        if password != password_confirm:
            flash('パスワードが一致しません。')
            return render_template('register.html')
        
        is_strong, message = is_password_strong(password)
        if not is_strong:
            flash(message)
            return render_template('register.html')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        placeholder = '%s' if conn.__class__.__module__ != 'sqlite3' else '?'
        
        sql_check = f'SELECT id FROM users WHERE username = {placeholder} OR email = {placeholder}'
        cursor.execute(sql_check, (username, email))
        if cursor.fetchone():
            flash('そのユーザー名またはメールアドレスは既に使用されています。')
            cursor.close()
            conn.close()
            return render_template('register.html')
        
        sql_insert = f'INSERT INTO users (username, email, password) VALUES ({placeholder}, {placeholder}, {placeholder})'
        cursor.execute(sql_insert, (username, email, generate_password_hash(password)))
        conn.commit()
        cursor.close()
        conn.close()

        token = s.dumps(email, salt='email-confirm')
        confirm_url = url_for('confirm_email', token=token, _external=True)
        send_email(email, "アカウントの有効化をお願いします", 'email/activate.html', confirm_url=confirm_url)
        
        flash('確認メールを送信しました。メールボックスを確認してアカウントを有効化してください。')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
        conn = get_db_connection()
        cursor = conn.cursor()
        placeholder = '%s' if conn.__class__.__module__ != 'sqlite3' else '?'
        sql = f'UPDATE users SET email_verified = TRUE WHERE email = {placeholder}'
        cursor.execute(sql, (email,))
        conn.commit()
        cursor.close()
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
        username = request.form.get('username')
        password = request.form.get('password')
        conn = get_db_connection()
        cursor = conn.cursor()
        placeholder = '%s' if conn.__class__.__module__ != 'sqlite3' else '?'
        sql = f'SELECT * FROM users WHERE username = {placeholder}'
        cursor.execute(sql, (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and user['email_verified'] and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            send_email(user['email'], "【重要】ログイン通知", 'email/login_alert.html', username=user['username'])
            return redirect(url_for('account'))
        
        flash('ユーザー名、パスワードが正しくないか、アカウントが有効化されていません。')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    # 本番環境ではS3から直接配信されるため、このルートは開発用
    return send_from_directory('uploads', filename)

# --- パスワードリセット関連のルート ---
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        conn = get_db_connection()
        cursor = conn.cursor()
        placeholder = '%s' if conn.__class__.__module__ != 'sqlite3' else '?'
        sql = f'SELECT id FROM users WHERE email = {placeholder}'
        cursor.execute(sql, (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if user:
            token = s.dumps(email, salt='password-reset')
            reset_url = url_for('reset_password', token=token, _external=True)
            send_email(email, "パスワードのリセット", 'email/reset_password.html', reset_url=reset_url)
            
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
        password = request.form.get('password')
        password_confirm = request.form.get('password_confirm')

        if not all([password, password_confirm]):
            flash('新しいパスワードを入力してください。')
            return render_template('reset_password.html', token=token)
        if password != password_confirm:
            flash('パスワードが一致しません。')
            return render_template('reset_password.html', token=token)
        
        is_strong, message = is_password_strong(password)
        if not is_strong:
            flash(message)
            return render_template('reset_password.html', token=token)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        placeholder = '%s' if conn.__class__.__module__ != 'sqlite3' else '?'
        sql = f'UPDATE users SET password = {placeholder} WHERE email = {placeholder}'
        cursor.execute(sql, (generate_password_hash(password), email))
        conn.commit()
        cursor.close()
        conn.close()
        
        flash('パスワードが更新されました。新しいパスワードでログインしてください。')
        return redirect(url_for('login'))
        
    return render_template('reset_password.html', token=token)


if __name__ == '__main__':
    # 開発環境でのみ実行される
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    if not os.path.exists('static/thumbnails'):
        os.makedirs('static/thumbnails')
    
    # データベースがない場合は初期化 (SQLite用)
    if not os.environ.get('DATABASE_URL') and not os.path.exists('database.db'):
        init_db()

    app.run(debug=True, host='0.0.0.0', port=5000)






