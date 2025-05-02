# уязвимости: 
#       A03:2021-Injection                                                       SQL-инъекции                   Утечка данных       Удаление или изменение данных. 
#       A01:2021 - Broken Access Control                                  Уязвимость возникает, когда приложение не проверяет права доступа пользователя перед выполнением действий
#       A07:2021 - Identification and Authentication Failures              Уязвимости, связанные с неправильной реализацией аутентификации и идентификации пользователей. Это включает слабые пароли, отсутствие блокировки учетных записей после множества неудачных попыток и хранение паролей в открытом виде.
#       A05:2021 - Security Misconfiguration                                Уязвимость возникает, когда приложение, сервер или база данных настроены неправильно. Это может быть связано с использованием стандартных учетных данных, включением ненужных функций или отсутствием обновлений.
from flask import Flask, request, render_template
import sqlite3

app = Flask(__name__)
app.config['WTF_CSRF_ENABLED'] = True

def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)')
    conn.commit()
    conn.close()

init_db()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']   # A04: Insecure Design
        role = 'user'                         # Пароли хранятся в БД как есть. При утечке базы злоумышленник получит все пароли.

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute(f"INSERT INTO users (username, password, role) VALUES ('{username}', '{password}', '{role}')")    #  A03:2021-Injection
        #cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, password, role))

        # если ввести в поле username специально отформатированную строку, можно изменить логику запроса
        # пример: admin', 'password', 'admin') --   (все, что будет после -- будет считаться комментарием)

        conn.commit()
        conn.close()
        
        return render_template('back.html')
    return render_template('register.html')

@app.route('/admin')
def admin():
  
    if request.args.get('role') == 'admin':     # A01:2021 - Broken Access Control
        # роль пользователя передается через параметр url запроса, приложение не проверяет. какая роль у пользователя на самом деле,
        # поэтому можно просто изменить url запрос и получить доступ к защищенной функциональности 
        return 'Welcome, Admin!'
    return 'Access Denied'

@app.route('/')
def home():
    return render_template('index.html')  

if __name__ == '__main__':
    app.run(debug=True)     # A05: Security Misconfiguration  
                            # В продакшене debug-режим раскрывает трассировки стека, что помогает атакующим
