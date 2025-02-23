import sqlite3
import os
import threading
import socket
import logging
from flask import Flask, request, render_template, redirect, url_for, session

app = Flask(__name__)
app.secret_key = 'SUPER_SECRET_KEY'

logging.basicConfig(
    filename='honeypot.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)

DB_NAME = 'honeypot.db'


def init_db():
    """Создаём таблицы: users, products. Заполняем тестовыми записями."""
    if os.path.exists(DB_NAME):
        os.remove(DB_NAME)  # Для чистоты эксперимента удалим старую БД

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # 1. Таблица пользователей
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            credit_card TEXT,
            is_admin INTEGER DEFAULT 0
        );
    ''')

    # Добавим тестовых пользователей
    users_data = [
        ("admin", "admin123", "1111-2222-3333-4444", 1),  # admin
        ("user1", "pass1", "5555-6666-7777-8888", 0),
        ("user2", "pass2", "1234-5678-9012-3456", 0),
    ]
    cursor.executemany(
        "INSERT INTO users(username, password_hash, credit_card, is_admin) VALUES (?,?,?,?)",
        users_data
    )

    # 2. Таблица товаров
    cursor.execute('''
        CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            price REAL
        );
    ''')

    # Добавим тестовые товары
    products_data = [
        ("PlayStation 5", 499.99),
        ("iPhone 14", 999.99),
        ("Samsung TV 55", 699.00),
        ("Lenovo Laptop", 450.00),
        ("Xiaomi Vacuum", 250.50),
    ]
    cursor.executemany("INSERT INTO products(name, price) VALUES (?,?)", products_data)

    conn.commit()
    conn.close()
    logging.info("Database initialized with sample users and products.")


def get_db_connection():
    """Помощник для подключения к БД."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def port_listener(port):
    """Примитивный TCP-сервер для логирования подключений (сканирование портов)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('0.0.0.0', port))
    sock.listen(5)
    logging.info(f"[*] Listening on port {port} for scanning attempts")

    while True:
        client_socket, addr = sock.accept()
        logging.warning(f"Port scan or connection attempt on port {port} from {addr}")
        client_socket.close()


def run_port_listeners(ports):
    """Запуск в отдельных потоках прослушки указанных портов."""
    for p in ports:
        t = threading.Thread(target=port_listener, args=(p,), daemon=True)
        t.start()


@app.before_request
def detect_dirsearch():
    user_agent = request.headers.get('User-Agent', '')
    path = request.path
    if 'dirsearch' in user_agent.lower():
        logging.warning(f"[Dirsearch detected] UA={user_agent}, IP={request.remote_addr}, path={path}")


@app.errorhandler(404)
def page_not_found(e):
    logging.warning(f"404 for path={request.path}, IP={request.remote_addr}")
    return "<h1>404 Not Found</h1>", 404


@app.route('/')
def index():
    return render_template('base.html', title="Добро пожаловать в наш магазин")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        logging.info(f"Login attempt: username={username}, pass={password}, IP={request.remote_addr}")

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and user["password_hash"] == password:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = (user['is_admin'] == 1)
            logging.info(f"User {username} logged in successfully.")
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="Неверный логин или пароль")

    return render_template('login.html')


@app.route('/search', methods=['GET', 'POST'])
def search():
    """
    Ищем товары по названию. Уязвимость: сырая конкатенация строки в SQL.
    Можно использовать SQL-инъекцию вида:
      ' OR '1'='1' UNION SELECT username, password_hash FROM users --
    чтобы вытащить данные пользователей.
    """
    results = []
    error = None
    query_string = ""

    if request.method == 'POST':
        query_string = request.form.get('query', '')

        logging.info(f"Search query: {query_string} IP={request.remote_addr}")

        # РЕАЛЬНО так делать нельзя — это демонстрация уязвимости
        # Число столбцов: name (TEXT), price (REAL)
        # Для UNION нужно также 2 столбца из другой таблицы.
        # Пример вредоносного инпута:
        #  a' OR '1'='1' UNION SELECT username, password_hash FROM users --

        conn = get_db_connection()
        cursor = conn.cursor()
        full_query = f"SELECT name, price FROM products WHERE name LIKE '%{query_string}%'"

        try:
            cursor.execute(full_query)
            results = cursor.fetchall()
        except Exception as e:
            error = str(e)

        conn.close()

    return render_template('search.html', results=results, error=error, query=query_string)


@app.route('/admin', methods=['GET', 'POST'])
def admin_page():
    if not session.get('is_admin'):
        return "<h1>Доступ запрещён</h1>", 403

    if request.method == 'POST':
        user_id_to_delete = request.form.get('user_id', '')
        if user_id_to_delete.isdigit():
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM users WHERE id=?", (user_id_to_delete,))
            conn.commit()
            conn.close()
            logging.warning(f"Admin deleted user_id={user_id_to_delete}")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, is_admin FROM users")
    all_users = cursor.fetchall()
    conn.close()

    return render_template('admin.html', users=all_users)


if __name__ == '__main__':
    init_db()
    ports_to_monitor = [21, 23, 8081]
    run_port_listeners(ports_to_monitor)
    app.run(host='0.0.0.0', port=5000, debug=False)
