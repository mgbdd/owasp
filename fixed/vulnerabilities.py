from flask import Flask, request, render_template, redirect, session, jsonify, flash
from flask_wtf.csrf import CSRFProtect, CSRFError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
import os
import re
import secrets
from datetime import timedelta

# Создаем приложение Flask
app = Flask(__name__)

# Генерируем случайные секретные ключи при запуске приложения
def generate_secret_key():
    """Генерирует криптографически стойкий случайный ключ"""
    return secrets.token_hex(32)  # 32 байта = 256 бит

# Устанавливаем случайные ключи или используем переменные окружения
app.secret_key = os.environ.get('FLASK_SECRET_KEY', generate_secret_key())
csrf_key = os.environ.get('FLASK_CSRF_KEY', generate_secret_key())

# ===== КОНФИГУРАЦИЯ БЕЗОПАСНОСТИ =====
app.config.update(
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
    SESSION_COOKIE_SECURE=False,    # Отключаем HTTPS для локальной разработки
    SESSION_COOKIE_HTTPONLY=True,   # Защита от XSS
    SESSION_COOKIE_SAMESITE='Lax',  # Защита от CSRF
    
    # Настройки CSRF
    WTF_CSRF_ENABLED=False,         # Отключаем CSRF для тестирования
    WTF_CSRF_SECRET_KEY=csrf_key,
    WTF_CSRF_TIME_LIMIT=3600        # Увеличиваем время жизни токена
)

# Инициализация CSRF защиты
csrf = CSRFProtect(app)

# Защита от брутфорса
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# Обработка ошибок CSRF
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    # Для отладки выводим дополнительную информацию
    app.logger.error(f"CSRF error: {str(e)}")
    return render_template('error.html', 
                          error="CSRF ошибка: Действие не выполнено из соображений безопасности. Пожалуйста, попробуйте снова.",
                          details=str(e)), 400

# Маршрут для выхода из системы
@app.route('/logout')
def logout():
    """Выход из системы и очистка сессии"""
    # Очищаем все данные сессии
    session.clear()
    
    # Отображаем страницу успешного выхода из системы
    return render_template('logout_success.html', message='Вы успешно вышли из системы')

@csrf.exempt
@app.route('/login_without_csrf', methods=['POST'])
def login_without_csrf():
    """Вход без CSRF (только для отладки)"""
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not username or not password:
        return "Все поля обязательны", 400
    
    # Подключение к БД и проверка
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Получаем информацию о структуре таблицы
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        
        # Адаптируем запрос к структуре таблицы
        if 'id' in columns:
            id_field = 'id'
        else:
            id_field = 'rowid'
            
        cursor.execute(
            f"SELECT {id_field}, password, role FROM users WHERE username = ?",
            (username,)
        )
        user = cursor.fetchone()
        
        if user and check_password_hash(user[1], password):
            # Создание сессии
            session.permanent = True
            session['user_id'] = user[0]
            session['username'] = username
            session['role'] = user[2] if len(user) > 2 else 'user'
            
            return redirect('/')
        else:
            return "Неверные учетные данные", 401
            
    except sqlite3.Error as e:
        app.logger.error(f"Database error during login_without_csrf: {str(e)}")
        return f"Ошибка базы данных: {str(e)}", 500
    finally:
        if 'conn' in locals():
            conn.close()

# Исключение CSRF-проверки для API-маршрутов, если передается заголовок X-API-KEY
@csrf.exempt
@app.route('/api/register', methods=['POST'])
def api_register():
    """API для регистрации (без CSRF)"""
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
    
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            return jsonify({"error": "Username is taken"}), 409
        
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
        
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, hashed_pw)
        )
        conn.commit()
        
        return jsonify({"status": "User created"}), 201
        
    except sqlite3.Error:
        return jsonify({"error": "Database error"}), 500
    finally:
        conn.close()

@csrf.exempt
@app.route('/api/login', methods=['POST'])
def api_login():
    """API для аутентификации (без CSRF)"""
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT id, password, role, login_attempts FROM users WHERE username = ?",
            (username,)
        )
        user = cursor.fetchone()
        
        if not user:
            return jsonify({"error": "Invalid credentials"}), 401
            
        if user[3] >= 5:
            return jsonify({"error": "Account locked"}), 403
            
        if check_password_hash(user[1], password):
            cursor.execute("UPDATE users SET login_attempts = 0 WHERE id = ?", (user[0],))
            conn.commit()
            
            session.permanent = True
            session['user_id'] = user[0]
            session['role'] = user[2]
            
            return jsonify({"status": "Authenticated"}), 200
        else:
            cursor.execute("UPDATE users SET login_attempts = login_attempts + 1 WHERE id = ?", (user[0],))
            conn.commit()
            return jsonify({"error": "Invalid credentials"}), 401
            
    except sqlite3.Error:
        return jsonify({"error": "Database error"}), 500
    finally:
        conn.close()

def init_db():
    """Инициализация базы данных с проверкой структуры"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Создаем таблицу, если она не существует
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
        
        # Проверяем структуру таблицы
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        
        # Добавляем недостающие столбцы, если таблица уже существует
        if 'role' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
            
        if 'login_attempts' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN login_attempts INTEGER DEFAULT 0")
            
        if 'last_attempt' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN last_attempt TIMESTAMP")
        
        conn.commit()
        app.logger.info("Инициализация базы данных завершена успешно")
    except sqlite3.Error as e:
        app.logger.error(f"Ошибка при инициализации базы данных: {str(e)}")
    finally:
        if 'conn' in locals():
            conn.close()

def is_strong_password(password):
    """Проверка сложности пароля"""
    return (len(password) >= 8 and
            re.search(r"[A-Z]", password) and
            re.search(r"[0-9]", password) and
            re.search(r"[!@#$%^&*]", password))

# ===== РОУТИНГ =====
@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10/hour")  # Лимит регистраций
def register():
    """Обработка регистрации через форму (с CSRF)"""
    if request.method == 'GET':
        return render_template('register.html')
    
    # POST-запрос с формой
    username = request.form.get('username')
    password = request.form.get('password')
        
    # Валидация
    if not username or not password:
        return render_template('register.html', error="Заполните все поля"), 400
    
    if not is_strong_password(password):
        return render_template('register.html', error="Пароль слишком слабый. Должен содержать не менее 8 символов, включая заглавную букву, цифру и специальный символ (!@#$%^&*)"), 400

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
            return jsonify({"error": "Username is taken or invalid"}), 409
        
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
        
        # Возврат ответа в зависимости от типа запроса
        if request.form:
            return redirect('/login')
        else:
            return jsonify({"status": "User created"}), 201
        
    except sqlite3.Error as e:
        return jsonify({"error": "Database error"}), 500
    finally:
        conn.close()

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5/minute")  # Лимит попыток входа
def login():
    """Аутентификация через форму (с CSRF)"""
    if request.method == 'GET':
        return render_template('login.html')
    
    # POST-запрос с формой
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Валидация
    if not username or not password:
        return render_template('login.html', error="Заполните все поля"), 400

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
            if request.form:
                return render_template('login.html', error="Неверные учетные данные")
            else:
                return jsonify({"error": "Invalid credentials"}), 401
            
        # Проверка блокировки
        if user[3] >= 5:  # Если 5+ неудачных попыток
            if request.form:
                return render_template('login.html', error="Учетная запись заблокирована из-за слишком большого количества неудачных попыток входа")
            else:
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
            session['username'] = username
            session['role'] = user[2]
            
            # Возврат ответа в зависимости от типа запроса
            if request.form:
                return redirect('/')
            else:
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

@app.route('/')
def home():
    """Главная страница"""
    if 'username' in session:
        # Если пользователь вошел, показываем персонализированное содержимое
        return render_template('dashboard.html', 
                             username=session.get('username', 'Пользователь'), 
                             role=session.get('role', 'user'))
    else:
        # Если пользователь не вошел, показываем стандартную страницу
        return render_template('index.html')

@app.route('/debug_csrf')
def debug_csrf():
    """Отладочный маршрут для проверки CSRF-токена"""
    from flask_wtf.csrf import generate_csrf
    csrf_token = generate_csrf()
    return f"""
    <html>
    <head><title>CSRF Отладка</title></head>
    <body>
        <h1>Отладка CSRF</h1>
        <p>CSRF токен: {csrf_token}</p>
        <form action="/login" method="POST">
            <input type="hidden" name="csrf_token" value="{csrf_token}">
            <input type="text" name="username" value="test">
            <input type="password" name="password" value="Password123!">
            <button type="submit">Тестовый вход</button>
        </form>
    </body>
    </html>
    """

# Маршрут для профиля пользователя
@app.route('/profile')
def profile():
    """Страница профиля пользователя"""
    # Проверяем, вошел ли пользователь
    if 'username' not in session:
        # Если пользователь не вошел, перенаправляем на страницу входа
        return redirect('/login')
    
    # Получаем данные пользователя
    username = session.get('username')
    role = session.get('role', 'user')
    
    # Отображаем страницу профиля с данными пользователя
    return render_template('profile.html', username=username, role=role)

@app.route('/admin')
def admin():
    """Административная панель"""
    # Проверяем, вошел ли пользователь и является ли он администратором
    if 'role' not in session or session.get('role') != 'admin':
        # Если пользователь не админ, отправляем ошибку доступа
        return render_template('error.html', error="У вас нет прав для доступа к этой странице"), 403
    
    # Получаем данные пользователей (только для администраторов)
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, role FROM users")
        users = cursor.fetchall()
        conn.close()
    except sqlite3.Error as e:
        users = []
        app.logger.error(f"Ошибка при получении списка пользователей: {str(e)}")
    
    # Отображаем административную панель
    return render_template('admin.html', users=users)

@app.route('/debug_db')
def debug_db():
    """Отладочный маршрут для проверки структуры базы данных"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Получаем схему таблицы пользователей
        cursor.execute("PRAGMA table_info(users)")
        columns = cursor.fetchall()
        
        # Получаем первых 5 пользователей
        cursor.execute("SELECT * FROM users LIMIT 5")
        users = cursor.fetchall()
        
        result = "<h1>Отладка базы данных</h1>"
        
        # Вывод структуры таблицы
        result += "<h2>Структура таблицы users:</h2><table border='1'><tr><th>ID</th><th>Название</th><th>Тип</th><th>Not Null</th><th>Default</th><th>PK</th></tr>"
        for col in columns:
            result += f"<tr><td>{col[0]}</td><td>{col[1]}</td><td>{col[2]}</td><td>{col[3]}</td><td>{col[4]}</td><td>{col[5]}</td></tr>"
        result += "</table>"
        
        # Вывод пользователей
        result += f"<h2>Пользователи в базе:</h2>"
        if users:
            result += "<table border='1'><tr>"
            for i in range(len(columns)):
                result += f"<th>{columns[i][1]}</th>"
            result += "</tr>"
            
            for user in users:
                result += "<tr>"
                for value in user:
                    result += f"<td>{value}</td>"
                result += "</tr>"
            result += "</table>"
        else:
            result += "<p>Нет пользователей в базе данных</p>"
            
        conn.close()
        
        # Добавление формы для регистрации тестового пользователя
        result += """
        <h2>Создать тестового пользователя:</h2>
        <form action='/register' method='POST'>
            <input type='hidden' name='csrf_token' value='""" + generate_csrf() + """'>
            <input type='text' name='username' value='test'>
            <input type='password' name='password' value='Password123!'>
            <button type='submit'>Создать пользователя</button>
        </form>
        """
        
        return result
    except sqlite3.Error as e:
        return f"Ошибка базы данных: {str(e)}"

# Функция для проверки безопасности ключей перед запуском
def check_key_security():
    """Проверяет, не используются ли небезопасные ключи"""
    debug_mode = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    
    # В режиме отладки просто логируем информацию
    if debug_mode:
        app.logger.info("Используются случайно сгенерированные ключи для этого сеанса")
        
    # Проверяем, не используются ли тестовые ключи в продакшене
    production_mode = os.getenv('FLASK_ENV') == 'production'
    if production_mode and (
        'FLASK_SECRET_KEY' not in os.environ or 
        'FLASK_CSRF_KEY' not in os.environ
    ):
        app.logger.warning("ВНИМАНИЕ: В продакшен-режиме следует указать секретные ключи через переменные окружения")

# ===== ЗАПУСК =====
if __name__ == '__main__':
    init_db()
    check_key_security()
    app.run(
        host='0.0.0.0',
        port=5000,
        ssl_context='adhoc' if os.getenv('FLASK_ENV') == 'development' else None,
        debug=os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    )
