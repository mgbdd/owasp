from flask import Flask, request, render_template, redirect, session, jsonify
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
import os
import re
from datetime import timedelta

app = Flask(__name__)

# ===== КОНФИГУРАЦИЯ БЕЗОПАСНОСТИ =====
app.secret_key = os.urandom(32)  # Случайный ключ
app.config.update(
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
    SESSION_COOKIE_SECURE=True,    # Только HTTPS
    SESSION_COOKIE_HTTPONLY=True,  # Защита от XSS
    SESSION_COOKIE_SAMESITE='Lax', # Защита от CSRF
    WTF_CSRF_ENABLED=True          # Включение CSRF
)

# Защита от брутфорса
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

csrf = CSRFProtect(app)

# ===== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ =====
def init_db():
    """Инициализация БД с минимальными правами"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            login_attempts INTEGER DEFAULT 0,
            last_attempt TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def is_strong_password(password):
    """Проверка сложности пароля"""
    return (len(password) >= 8 and
            re.search(r"[A-Z]", password) and
            re.search(r"[0-9]", password) and
            re.search(r"[!@#$%^&*]", password))

# ===== РОУТИНГ =====
@app.route('/register', methods=['POST'])
@limiter.limit("10/hour")  # Лимит регистраций
def register():
    """Обработка регистрации (только POST)"""
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Валидация
    if not username or not password:
        return jsonify({"error": "All fields required"}), 400
    
    if not is_strong_password(password):
        return jsonify({"error": "Password too weak"}), 400

    # Безопасное подключение к БД
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Проверка существующего пользователя
        cursor.execute(
            "SELECT username FROM users WHERE username = ?", 
            (username,)
        )
        if cursor.fetchone():
            return jsonify({"error": "User exists"}), 409
        
        # Хеширование пароля
        hashed_pw = generate_password_hash(
            password,
            method='pbkdf2:sha256',
            salt_length=16
        )
        
        # Безопасная вставка
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, hashed_pw)
        )
        conn.commit()
        
        return jsonify({"status": "User created"}), 201
        
    except sqlite3.Error as e:
        return jsonify({"error": "Database error"}), 500
    finally:
        conn.close()

@app.route('/login', methods=['POST'])
@limiter.limit("5/minute")  # Лимит попыток входа
def login():
    """Аутентификация (только POST)"""
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Получаем данные пользователя
        cursor.execute(
            "SELECT id, password, role, login_attempts FROM users WHERE username = ?",
            (username,)
        )
        user = cursor.fetchone()
        
        if not user:
            return jsonify({"error": "Invalid credentials"}), 401
            
        # Проверка блокировки
        if user[3] >= 5:  # Если 5+ неудачных попыток
            return jsonify({"error": "Account locked"}), 403
            
        # Проверка пароля
        if check_password_hash(user[1], password):
            # Сброс счетчика попыток
            cursor.execute(
                "UPDATE users SET login_attempts = 0 WHERE id = ?",
                (user[0],)
            )
            conn.commit()
            
            # Создание сессии
            session.permanent = True
            session['user_id'] = user[0]
            session['role'] = user[2]
            
            return jsonify({"status": "Authenticated"}), 200
        else:
            # Увеличиваем счетчик попыток
            cursor.execute(
                "UPDATE users SET login_attempts = login_attempts + 1 WHERE id = ?",
                (user[0],)
            )
            conn.commit()
            return jsonify({"error": "Invalid credentials"}), 401
            
    except sqlite3.Error as e:
        return jsonify({"error": "Database error"}), 500
    finally:
        if 'conn' in locals():
            conn.close()

# ===== ЗАПУСК =====
if __name__ == '__main__':
    init_db()
    app.run(
        host='0.0.0.0',
        port=5000,
        ssl_context='adhoc' if os.getenv('FLASK_ENV') == 'development' else None,
        debug=os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    )
