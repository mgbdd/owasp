# уязвимости: 
#       A03:2021-Injection                                                       SQL-инъекции                   Утечка данных       Удаление или изменение данных. 
#       A01:2021 - Broken Access Control                                  Уязвимость возникает, когда приложение не проверяет права доступа пользователя перед выполнением действий
#       A07:2021 - Identification and Authentication Failures              Уязвимости, связанные с неправильной реализацией аутентификации и идентификации пользователей. Это включает слабые пароли, отсутствие блокировки учетных записей после множества неудачных попыток и хранение паролей в открытом виде.
#       A05:2021 - Security Misconfiguration                                Уязвимость возникает, когда приложение, сервер или база данных настроены неправильно. Это может быть связано с использованием стандартных учетных данных, включением ненужных функций или отсутствием обновлений.
from flask import Flask, request, render_template, session, redirect, url_for 
import sqlite3

app = Flask(__name__)
app.secret_key = 'ultra_secret_key'

def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)')
    conn.commit()
    conn.close()

init_db()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn =sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and user[2] == password:
            session['username'] = user[1]
            session['role'] = user[3]
            return redirect(url_for('home'))
        return 'Invalid credentials'
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = 'user'  

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, password, role))
        # параметризованные запросы автоматически экранируют пользовательский ввод, предотвращая SQL-инъекции
        # Даже если ввести вредоносные данные, они будут обработаны как обычные строки, а не как часть SQL-запроса

        conn.commit()
        conn.close()
        
        return render_template('back.html')
    return render_template('register.html')

@app.route('/admin')
def admin():
    if 'username' not in session:
        return redirect(url_for('login'))

    if session.get('role') == 'admin':  # Проверка роли через сессию
        return 'Welcome, Admin!'
    return 'Access Denied'

@app.route('/')
def home():
    return render_template('index.html')  

if __name__ == '__main__':
    app.run(debug=True)