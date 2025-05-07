from flask import Flask, request, render_template, redirect, session
from flask_wtf.csrf import CSRFProtect
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Генерация безопасного секретного ключа
app.config['WTF_CSRF_ENABLED'] = True  # Включаем CSRF защиту
csrf = CSRFProtect(app)  # A05: Исправлено

# Настройки сессии
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True

def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = 'user'

        # Валидация ввода
        if not username or not password:
            return "Please fill all fields", 400
        
        # Проверка сложности пароля
        if len(password) < 8:
            return "Password must be at least 8 characters", 400

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()

        try:
            # Безопасная проверка существующего пользователя
            cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                # A04: Исправлено - унифицированное сообщение
                return "Registration failed. Please try again with different credentials.", 400
            
            # Хеширование пароля (A07: Исправлено)
            hashed_password = generate_password_hash(password)
            
            # Параметризованный запрос (A03: Исправлено)
            cursor.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, hashed_password, role)
            )
            conn.commit()
            
        except sqlite3.Error as e:
            return f"Database error: {str(e)}", 500
        finally:
            conn.close()

        return redirect('/login')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute(
            "SELECT password, role FROM users WHERE username = ?", 
            (username,)
        )
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[0], password):
            # Создаем сессию (A01: Исправлено)
            session.permanent = True
            session['username'] = username
            session['role'] = user[1]
            return redirect('/')
        
        return "Invalid credentials", 401
    
    return render_template('login.html')

@app.route('/admin')
def admin():
    # Проверка аутентификации и прав через сессию (A01: Исправлено)
    if 'role' not in session or session.get('role') != 'admin':
        return 'Access Denied', 403
    return 'Welcome, Admin!'

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/')
def home():
    if 'username' in session:
        return f'Welcome {session["username"]}!'
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=False)  # A05: Исправлено (debug отключен)
