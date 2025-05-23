# уязвимости: 
#       A03:2021-Injection                                                       SQL-инъекции                   Утечка данных       Удаление или изменение данных. 
#       A01:2021 - Broken Access Control                                  Уязвимость возникает, когда приложение не проверяет права доступа пользователя перед выполнением действий
#       A07:2021 - Identification and Authentication Failures              Уязвимости, связанные с неправильной реализацией аутентификации и идентификации пользователей. Это включает слабые пароли, отсутствие блокировки учетных записей после множества неудачных попыток и хранение паролей в открытом виде.
#       A05:2021 - Security Misconfiguration                                Уязвимость возникает, когда приложение, сервер или база данных настроены неправильно. Это может быть связано с использованием стандартных учетных данных, включением ненужных функций или отсутствием обновлений.
#       A04:2021 - Insecure Design                                      

from flask import Flask, request, render_template
import sqlite3


app = Flask(__name__)   # Broken Access Control       A01       
app.config['WTF_CSRF_ENABLED'] = False

# CSRF - атака, при которой злоумышленник заставляет жертву выполнить нежелательные действия в веб-приложении без её ведома.

def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)')
    conn.commit()
    conn.close()

init_db()

@app.route('/register', methods=['GET', 'POST'])    #  Broken Access Control  +  Security Misconfiguration
#  register принимает POST-запросы (небезопасный метод), не проверяет CSRF-токен и хранит пароли в открытом виде
#                                                                              -> откуда возникает доп угроза Insecure Design
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']   # A07:2021 - Identification and Authentication Failures 
        role = 'user'                         # Пароли хранятся в БД как есть. При утечке базы злоумышленник получит все пароли.

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()

         # A04: Insecure Design - Username Enumeration
        try:
            cursor.execute(f"SELECT username FROM users WHERE username = '{username}'")
            if  cursor.fetchone():
                return "Username already taken. Please choose another username."
        except sqlite3.OperationalError:
            pass

        cursor.executescript(f"""
            INSERT INTO users (username, password, role)
            VALUES ('{username}', '{password}', '{role}');           #  A03:2021-Injection
            """)
   
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
        # http://127.0.0.1:5000/admin?role=admin
        return 'Welcome, Admin!'
    return 'Access Denied'

@app.route('/')
def home():
    return render_template('index.html')  

if __name__ == '__main__':
    app.run(debug=True)     # A05 Security Misconfiguration  
                            # В продакшене debug-режим раскрывает трассировки стека, что помогает атакующим
                            # (злоумышленник видит внутреннюю структуру кода, пути к файлам, переменные).