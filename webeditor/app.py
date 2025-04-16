from flask import Flask, request, jsonify, session, redirect, render_template, url_for, g, make_response, abort, flash, send_from_directory
from flask_bcrypt import Bcrypt 
from ldap3 import Server, Connection, ALL
from datetime import timedelta
from itsdangerous import URLSafeTimedSerializer
from email.mime.text import MIMEText
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import smtplib
import sqlite3
import json
import re
import bcrypt
import xml.etree.ElementTree as ET
import logging
import socket

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Конфигурация LDAP
LDAP_SERVER = os.getenv("LDAP_SERVER")
LDAP_PORT = int(os.getenv("LDAP_PORT"))
LDAP_USER = os.getenv("LDAP_USER")
LDAP_PASSWORD = os.getenv("LDAP_PASSWORD")
LDAP_SEARCH_BASE = os.getenv("LDAP_SEARCH_BASE")

# Конфигурация SMTP для отправки email
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = os.getenv("SMTP_PORT")
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SMTP_AUTH = bool(os.getenv("SMTP_AUTH"))
EMAIL_SALT = os.getenv("EMAIL_SALT")

# Подключение к базе данных SQLite
DATABASE = os.getenv("DATABASE")
SCHEMA = os.getenv("SCHEMA_SQL")
IP_LIST_FILE = os.getenv("IP_LIST_FILE")

PASSWORD_LEN = int(os.getenv("PASSWORD_LENGTH"))
PASSWORD_SALT = os.getenv("PASSWORD_SALT")

bcrypt = Bcrypt(app) 

app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")  # Секретный ключ для безопасности

# Настройка для генерации ссылок
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def send_email(to_email, subject, body):
    msg = MIMEMultipart()
    msg['Subject'] = subject
    msg['From'] = SMTP_USER
    msg["To"] = ", ".join(to_email)  # Преобразуем список в строку
    msg.attach(MIMEText(body, "plain"))
    text = msg.as_string()

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            if SMTP_AUTH:
                server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, to_email, text)
    except Exception as e:
        print(f"Ошибка при отправке письма: {e}")
        
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        with open(SCHEMA, "r", encoding="utf-8") as f:
            sql_script = f.read()
        cursor.executescript(sql_script)
        conn.commit()

def get_db_connection():
    conn = getattr(g, '_database', None)
    if conn is None:
        conn = g._database = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row
    return conn

def is_password_strong(password):
    # Проверка длины пароля
    if len(password) < PASSWORD_LEN:
        return False
    # Проверка наличия символов из разных групп
    groups = [
        r'[A-Z]',  # Заглавные латинские буквы
        r'[a-z]',  # Строчные латинские буквы
        r'\d',     # Цифры
        r'[!@#$%^&*(),.?":{}|<>]'  # Специальные символы
    ]
    matches = sum(bool(re.search(pattern, password)) for pattern in groups)
    return matches >= 3

def check_user_by_email(email):
    # Подключаемся к базе данных
    conn = get_db_connection()
    cursor = conn.cursor()

    # Выполняем запрос для поиска пользователя по email
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    
    # Получаем результат запроса
    user = cursor.fetchone()

    # Если пользователь найден, возвращаем True, иначе False
    return user is not None

def get_admin_emails():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT email FROM users WHERE is_admin = 1')
    admin_emails = [row[0] for row in cursor.fetchall()]
    conn.close()
    return admin_emails

def generate_reset_token(email):
    return serializer.dumps(email, salt=PASSWORD_SALT)

def send_reset_email(email, token):
    """
    Отправляет письмо с уникальной ссылкой для сброса пароля.
    """
    try:
        # Создаем текст письма
        subject = "Сброс пароля"
        reset_url = url_for('reset_password', token=token, _external=True)  # Генерация ссылки
        body = (
            f"Здравствуйте!\n\n"
            f"Вы запросили сброс пароля на ресурсе редактирования списков ip-адресов для митигатора.\n"
            f"Для сброса пароля перейдите по ссылке:\n"
            f"{reset_url}\n\n"
            f"Ссылка действительна в течение 1 часа.\n\n"
            f"Если вы не запрашивали сброс пароля, проигнорируйте это письмо.\n\n"
        )

        # Создаем объект MIMEText
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = SMTP_USER
        msg['To'] = email

        # Подключаемся к SMTP серверу и отправляем письмо
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()  # Включаем TLS шифрование
            if SMTP_AUTH:
                print("Trying to login")
                server.login() (SMTP_USER, SMTP_PASSWORD)  # Авторизуемся на сервере
            server.sendmail(SMTP_USER, [email], msg.as_string())  # Отправляем письмо

        return True
    except Exception as e:
        logger.error(f"Ошибка при отправке письма: {e}")
        logger.info(f"{reset_url}")
        return False

@app.route("/")
def home():
    return redirect(url_for('login'))

@app.route('/dib_blacklist')
def dib_blacklist():
    return send_from_directory('/data', 'dib_blacklist.txt',mimetype='text/plain;charset=UTF-8')

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico',mimetype='image/vnd.microsoft.icon')

@app.route("/iplisteditor")
def editor():
    if 'user_id' not in session:
        print(session)
        return redirect(url_for('login'))
    else:
        conn = get_db_connection()
        ip_list = conn.execute('SELECT ip_address FROM ip_addresses').fetchall()
        ip_list = [row['ip_address'] for row in ip_list]  # Преобразуем в список строк
        return render_template('listEditor.html', ip_list=ip_list)

@app.route('/get_ip_list', methods=['GET'])
def get_ip_list():
    if 'user_id' not in session:
        print(session)
        return redirect(url_for('login'))
    else:
        conn = get_db_connection()
        ip_list = conn.execute('SELECT ip_address FROM ip_addresses').fetchall()
        return jsonify({"ip_list": [row['ip_address'] for row in ip_list]})

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not re.fullmatch(r"[\w\-]+", username):
            logger.error("Некорректное имя пользователя. User id %s, ip %s", username, request.headers.get('X-Forwarded-For', request.remote_addr))
            return jsonify({'success': False, 'message': 'Ошибка в имени пользователя'}), 400
        
        if not password:
            logger.error("Неуспешная попытка входа. Empty password: username %s, ip: %s", username, request.headers.get('X-Forwarded-For', request.remote_addr))

        # Проверка входных данных
        if not username or not password:
            return jsonify({'error': 'Both username and password are required.'}), 400

        # Проверка данных пользователя
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password, enabled, is_admin FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if not user:
            logger.error("Неуспешная попытка входа. Wrong username - %s, ip - %s", username, request.headers.get('X-Forwarded-For', request.remote_addr))
            return jsonify({'status': 'error', 'message': 'Неверное имя пользователя или пароль'}), 401
        # Проверяем, активен ли пользователь        
        if user[3] != 1:  # enabled = 1 (активен)
            logger.error("Неуспешная попытка входа. Пользователь неактивен: id %s, username %s, admin role %s, ip %s", user[0], user[1], bool(user[4]), request.headers.get('X-Forwarded-For', request.remote_addr))
            return jsonify({'status': 'error', 'message': 'Пользователь неактивен'}), 403


        # Проверяем пароль
        if bcrypt.check_password_hash(user[2], password):  # user[2] - хэшированный пароль
            # Сохраняем данные пользователя в сессии
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['is_admin'] = user[4]
            session.permanent = True
            app.permanent_session_lifetime = timedelta(minutes=10)
            success = True
            redirect_url = url_for('editor')
            
            root = ET.Element('response')
            success_elem = ET.SubElement(root, 'success')
            success_elem.text = str(success).lower()
            redirect_url_elem = ET.SubElement(root, 'redirect_url')
            redirect_url_elem.text = redirect_url

            response_xml = ET.tostring(root, encoding='utf-8')
            response = make_response(response_xml)
            response.headers['Content-Type'] = 'application/xml'
            logger.info("%s вход в систему. Пользователь: id %s, username %s, admin role %s, ip %s", "Успешный", user[0], user[1], bool(user[4]), request.headers.get('X-Forwarded-For', request.remote_addr))
            return response
        else:
            logger.info("%s вход в систему. Пользователь: id %s, username %s, admin role %s, ip %s", "Неуспешный", user[0], user[1], bool(user[4]), request.headers.get('X-Forwarded-For', request.remote_addr))
            return jsonify({'status': 'error', 'message': 'Неверное имя пользователя или пароль'}), 401

    return render_template('login.html')

@app.route('/logout', methods=['GET'])
def logout():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM active_user WHERE id = 1")
        conn.commit()
    logger.info("Выход из системы системы. User %s, ip %s", session['user_id'], request.headers.get('X-Forwarded-For', request.remote_addr))
    session.pop('user_id')
    return redirect(url_for('login'))

@app.route('/save_ip_list', methods=['POST'])
def save_ip_list():
    # Получаем данные из POST-запроса
    if 'user_id' not in session:
        logger.error("Неавторизованная попытка изменить список. IP %s", request.headers.get('X-Forwarded-For', request.remote_addr))
        return abort(403) #redirect(url_for('login'))
    else:
        data = request.get_data().decode('utf-8')
        try:
            ip_data = json.loads(data)
            ip_list = ip_data.get('ip_list', '')
            for ip in ip_list:
                socket.inet_aton(ip)
            # Сохраняем список IP в базу данных
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("DELETE FROM ip_addresses;")
            conn.commit()
            c.execute("INSERT INTO history (ip_list, user_id) VALUES (?, ?)", (data, session['user_id']))
            conn.commit()
            c.executemany("INSERT INTO ip_addresses (ip_address) VALUES (?)", [(ip,) for ip in ip_list])
            conn.commit()
            # Сохраняем список IP в файл
            with open(IP_LIST_FILE, 'w') as file:
                file.write("\n".join(ip_list))
            logger.info("Успешное изменение списка. User id %s, ip %s", session['user_id'], request.headers.get('X-Forwarded-For', request.remote_addr))
            return jsonify({'message': 'Saved successfully'}), 200
        except OSError as e:
            return jsonify({'message': f'Ошибка в формате ip-адреса'}), 400
        except Exception as e:
            return jsonify({'message': f'Error: {str(e)}'}), 400

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user_name = request.form.get('user_name')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Пароли не совпадают.')
            return redirect(url_for('register'))

        if not is_password_strong(password):
            flash('Пароль не соответствует требованиям сложности.')
            return redirect(url_for('register'))

        # Логика сохранения пользователя (например, в БД)
        server = Server(LDAP_SERVER, port=LDAP_PORT, get_info=ALL)
        conn = Connection(server, user=LDAP_USER, password=LDAP_PASSWORD)
        if not conn.bind():
            return jsonify({'success': False, 'message': 'Ошибка подключения к LDAP'}), 500
        
        if not re.fullmatch(r"[\w\-]+", user_name):
            logger.error("Некорректное имя пользователя. User id %s, ip %s", user_name, request.headers.get('X-Forwarded-For', request.remote_addr))
            return jsonify({'success': False, 'message': 'Ошибка в имени пользователя'}), 400

        # Поиск пользователя в Active Directory
        conn.search(LDAP_SEARCH_BASE, f'(samaccountname={user_name})', attributes=['cn', 'mail', 'samaccountname'])
        if not conn.entries:
            return jsonify({'success': False, 'message': 'Пользователь не найден в Active Directory'}), 404

        user = conn.entries[0]
        samaccountname = user.samaccountname.value
        cn = user.cn.value
        email = user.mail.value
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Добавление пользователя в базу данных
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, password, cn, email) VALUES (?, ?, ?, ?)', (samaccountname, hashed_password, cn, email))
            conn.commit()
        except sqlite3.IntegrityError:
            return jsonify({'success': False, 'message': 'Пользователь уже существует'}), 400

        token = serializer.dumps(email, salt=EMAIL_SALT)
        confirm_url = url_for('confirm_email', token=token, _external=True)

        # Отправка email с подтверждением
        subject = 'Подтверждение регистрации'
        body = f'Здравствуйте! Работник {cn} зарегистрировался в системе редактирования списков митигатора.\n\nЕсли вы согласны предоставить такой доступ, перейдите по ссылке для активации аккаунта: {confirm_url}'
        try:
            send_email(get_admin_emails(), subject, body)
            return jsonify({'success': True, 'message': 'Регистрация прошла успешно! Письмо с подтверждением регистарции отправлено администратору\n\nОжидайте активации аккаунта администратором, на Вашу почту придет соответсвующее уведомление.'})
        except Exception as e:
            return f"Ошибка при отправке письма: {str(e)}"

    return render_template('register.html')

@app.route('/recover_password', methods=['POST'])
def recover_password():
    email = request.form.get('email')

    if not re.fullmatch(r"[\w\-@\.]+", email):
        logger.error("Некорректный email. email %s, ip %s", email, request.headers.get('X-Forwarded-For', request.remote_addr))
        return jsonify({'success': False, 'message': 'Ошибка в email'}), 400
    
    user_exists = check_user_by_email(email)
    print
    # Генерация токена и отправка письма
    if user_exists:
        token = generate_reset_token(email)
        logger.info("Запрос сброса пароля, email %s, ip %s", email, request.headers.get('X-Forwarded-For', request.remote_addr))
        if send_reset_email(email, token):
            return jsonify({'status': 'success', 'message': f'Письмо для сброса пароля отправлено на {email}'})
        else:
            return jsonify({'status': 'error', 'message': 'Не удалось отправить письмо'}), 500
    else:
        logger.error("Запрос сброса пароля на некорректный email %s, ip %s", email, request.headers.get('X-Forwarded-For', request.remote_addr))
        return jsonify({'status': 'error', 'message': f'Ошибка отправки письма на {email}'}), 400

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        # Проверка токена и его срока действия
        email = serializer.loads(token, salt=PASSWORD_SALT, max_age=3600)  # Токен действителен 1 час
    except:
        logger.error("Некорректная попытка сброса пароля. Использован токен %s, ip %s", token, request.headers.get('X-Forwarded-For', request.remote_addr))
        return "Недействительная или устаревшая ссылка для сброса пароля.", 400

    if request.method == 'POST':
        # Обработка формы сброса пароля
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            return "Пароли не совпадают.", 400
        
        if not is_password_strong(new_password):
            return "Пароль не соответствует требованиям сложности", 400

        # Обновление пароля в базе данных
        try:
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET password = ? WHERE email = ?", (hashed_password, email))
            conn.commit()
            return "Пароль успешно изменён."
        except Exception as e:
            print(f"Ошибка при обновлении пароля в базе данных: {e}")
            return "Произошла ошибка при обновлении пароля.", 500

    # Показ формы для ввода нового пароля
    return render_template('reset_password.html', token=token)

@app.route('/confirm/<token>')
def confirm_email(token):
    conn = get_db_connection()
    cursor = conn.cursor()
        
    try:
        email = serializer.loads(token, salt=EMAIL_SALT, max_age=3600)  # Срок действия токена - 1 час
    except Exception as e:
        logger.error("Некорректная попытка активации пользователя. Использован токен %s, ip %s", token, request.headers.get('X-Forwarded-For', request.remote_addr))
        return "Время действия ссылки истекло или ссылка недействительна."

    # Обновление статуса пользователя в базе данных
    try:
        # Проверяем, существует ли пользователь с указанным email
        cursor.execute("SELECT cn FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        if user:
            # Если пользователь найден, обновляем поле enabled на 1
            cursor.execute("UPDATE users SET enabled = 1 WHERE email = ?", (email,))
            conn.commit()
            # Отправка email с подтверждением
            subject = 'Подтверждение регистрации'
            body = f'Здравствуйте, {user[0]}!\nВаша учетная запись в системе редактирования списков митигатора активирована.\nТеперь вы можете войти в систему.'
            try:
                send_email(email, subject, body)
            except Exception as e:
                return f"Ошибка при отправке письма: {str(e)}"            
            return f"Пользователь {user[0]} активирован."
        else:
            # Если пользователь не найден
            return f"Пользователь с email {email} не найден."
    except sqlite3.Error as e:
        return f"Ошибка при работе с базой данных: {e}"

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

if __name__ == '__main__':
    init_db()
    app.run(host="0.0.0.0", port=6700, debug=True)
