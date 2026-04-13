import os
import sqlite3
import bcrypt

ADMIN_NAME = os.getenv("ADMIN_NAME", "Marcelo")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "marceloirmao@hotmail.com")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "199612")
GUEST_EMAIL = os.getenv("GUEST_EMAIL", "convidado@local.devdelivery")

# --- CONFIGURAÇÃO DO BANCO ---

def get_db():
    """Estabelece conexão com o banco de dados."""
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def _column_exists(cursor, table_name, column_name):
    columns = cursor.execute(f"PRAGMA table_info({table_name})").fetchall()
    return any(column[1] == column_name for column in columns)

def _ensure_default_categories(cursor):
    existing = cursor.execute("SELECT COUNT(*) FROM categories").fetchone()[0]
    if existing:
        return

    default_categories = [
        ("Porções", 1),
        ("Refrigerantes", 2),
    ]
    cursor.executemany(
        "INSERT INTO categories (name, display_order) VALUES (?, ?)",
        default_categories,
    )

def _ensure_default_delivery_areas(cursor):
    existing = cursor.execute("SELECT COUNT(*) FROM delivery_areas").fetchone()[0]
    if existing:
        return

    cursor.executemany(
        "INSERT INTO delivery_areas (name, delivery_fee, is_active) VALUES (?, ?, ?)",
        [
            ("Centro", 5.0, 1),
            ("Bairro Novo", 7.0, 1),
        ],
    )

def _ensure_store_settings(cursor):
    settings = cursor.execute("SELECT id FROM store_settings WHERE id = 1").fetchone()
    if settings:
        return

    cursor.execute(
        """
        INSERT INTO store_settings (
            id, store_name, tagline, opening_hours, is_open, delivery_mode, last_financial_reset
        ) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """,
        (
            1,
            "MJ Porções",
            "Porções caprichadas, entrega rápida e atendimento digital.",
            "Todos os dias, das 18h às 23h",
            1,
            "Entrega e retirada",
        ),
    )

def _hash_password(senha_pura):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(senha_pura.encode('utf-8'), salt).decode('utf-8')

def ensure_admin_user(conn):
    cursor = conn.cursor()
    admin = cursor.execute("SELECT id FROM users WHERE email = ?", (ADMIN_EMAIL,)).fetchone()

    if admin:
        cursor.execute(
            "UPDATE users SET nome = ?, is_admin = 1 WHERE email = ?",
            (ADMIN_NAME, ADMIN_EMAIL),
        )
    else:
        senha_hashed = _hash_password(ADMIN_PASSWORD)
        cursor.execute(
            "INSERT INTO users (nome, email, senha, whatsapp, is_admin) VALUES (?, ?, ?, ?, ?)",
            (ADMIN_NAME, ADMIN_EMAIL, senha_hashed, None, 1),
        )

def ensure_guest_user(conn):
    cursor = conn.cursor()
    guest = cursor.execute("SELECT id FROM users WHERE email = ?", (GUEST_EMAIL,)).fetchone()
    if guest:
        return guest['id']

    senha_hashed = _hash_password(os.getenv("GUEST_PASSWORD", "guest_not_used"))
    cursor.execute(
        "INSERT INTO users (nome, email, senha, whatsapp, is_admin) VALUES (?, ?, ?, ?, ?)",
        ("Convidado", GUEST_EMAIL, senha_hashed, None, 0),
    )
    return cursor.lastrowid

def init_db():
    """Cria as tabelas de usuários, produtos e pedidos se elas não existirem."""
    conn = get_db()
    cursor = conn.cursor()
    
    # 1. Tabela de Usuários
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        senha TEXT NOT NULL,
        whatsapp TEXT,
        is_admin INTEGER NOT NULL DEFAULT 0
    )
    """)

    if not _column_exists(cursor, 'users', 'is_admin'):
        cursor.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
    if not _column_exists(cursor, 'users', 'whatsapp'):
        cursor.execute("ALTER TABLE users ADD COLUMN whatsapp TEXT")

    # 2. Tabela de Produtos
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT NOT NULL,
        preco REAL NOT NULL,
        descricao TEXT DEFAULT '',
        image_path TEXT,
        category_id INTEGER,
        is_featured INTEGER NOT NULL DEFAULT 0,
        is_active INTEGER NOT NULL DEFAULT 1,
        FOREIGN KEY (category_id) REFERENCES categories (id)
    )
    """)

    if not _column_exists(cursor, 'products', 'descricao'):
        cursor.execute("ALTER TABLE products ADD COLUMN descricao TEXT DEFAULT ''")
    if not _column_exists(cursor, 'products', 'image_path'):
        cursor.execute("ALTER TABLE products ADD COLUMN image_path TEXT")
    if not _column_exists(cursor, 'products', 'category_id'):
        cursor.execute("ALTER TABLE products ADD COLUMN category_id INTEGER")
    if not _column_exists(cursor, 'products', 'is_featured'):
        cursor.execute("ALTER TABLE products ADD COLUMN is_featured INTEGER NOT NULL DEFAULT 0")
    if not _column_exists(cursor, 'products', 'is_active'):
        cursor.execute("ALTER TABLE products ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        display_order INTEGER NOT NULL DEFAULT 0
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS store_settings (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        store_name TEXT NOT NULL DEFAULT 'MJ Porções',
        tagline TEXT NOT NULL DEFAULT 'Porções caprichadas, entrega rápida e atendimento digital.',
        banner_image TEXT,
        profile_image TEXT,
        opening_hours TEXT NOT NULL DEFAULT 'Todos os dias, das 18h às 23h',
        is_open INTEGER NOT NULL DEFAULT 1,
        delivery_mode TEXT NOT NULL DEFAULT 'Entrega e retirada',
        last_financial_reset TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """)

    if not _column_exists(cursor, 'store_settings', 'last_financial_reset'):
        cursor.execute(
            "ALTER TABLE store_settings ADD COLUMN last_financial_reset TEXT"
        )
        cursor.execute(
            "UPDATE store_settings SET last_financial_reset = COALESCE(last_financial_reset, CURRENT_TIMESTAMP)"
        )

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS financial_closures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        period_start TEXT NOT NULL,
        period_end TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        orders_count INTEGER NOT NULL DEFAULT 0,
        gross_revenue REAL NOT NULL DEFAULT 0,
        delivered_revenue REAL NOT NULL DEFAULT 0,
        open_revenue REAL NOT NULL DEFAULT 0,
        canceled_revenue REAL NOT NULL DEFAULT 0,
        delivered_orders INTEGER NOT NULL DEFAULT 0,
        canceled_orders INTEGER NOT NULL DEFAULT 0,
        pending_orders INTEGER NOT NULL DEFAULT 0,
        in_preparation_orders INTEGER NOT NULL DEFAULT 0,
        on_the_way_orders INTEGER NOT NULL DEFAULT 0,
        closed_by_user_id INTEGER,
        FOREIGN KEY (closed_by_user_id) REFERENCES users (id)
    )
    """)

    if not _column_exists(cursor, 'financial_closures', 'delivered_revenue'):
        cursor.execute("ALTER TABLE financial_closures ADD COLUMN delivered_revenue REAL NOT NULL DEFAULT 0")
    if not _column_exists(cursor, 'financial_closures', 'open_revenue'):
        cursor.execute("ALTER TABLE financial_closures ADD COLUMN open_revenue REAL NOT NULL DEFAULT 0")
    if not _column_exists(cursor, 'financial_closures', 'canceled_revenue'):
        cursor.execute("ALTER TABLE financial_closures ADD COLUMN canceled_revenue REAL NOT NULL DEFAULT 0")

    # 3. Tabela de Pedidos (Atualizada com FK e Status padrão)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        customer_name TEXT,
        customer_phone TEXT,
        customer_address TEXT,
        customer_neighborhood TEXT,
        needs_change INTEGER NOT NULL DEFAULT 0,
        change_for REAL,
        payment_method TEXT,
        total REAL NOT NULL,
        status TEXT DEFAULT 'Pendente',
        data TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    """)

    if not _column_exists(cursor, 'orders', 'customer_name'):
        cursor.execute("ALTER TABLE orders ADD COLUMN customer_name TEXT")
    if not _column_exists(cursor, 'orders', 'customer_phone'):
        cursor.execute("ALTER TABLE orders ADD COLUMN customer_phone TEXT")
    if not _column_exists(cursor, 'orders', 'customer_address'):
        cursor.execute("ALTER TABLE orders ADD COLUMN customer_address TEXT")
    if not _column_exists(cursor, 'orders', 'customer_neighborhood'):
        cursor.execute("ALTER TABLE orders ADD COLUMN customer_neighborhood TEXT")
    if not _column_exists(cursor, 'orders', 'needs_change'):
        cursor.execute("ALTER TABLE orders ADD COLUMN needs_change INTEGER NOT NULL DEFAULT 0")
    if not _column_exists(cursor, 'orders', 'change_for'):
        cursor.execute("ALTER TABLE orders ADD COLUMN change_for REAL")
    if not _column_exists(cursor, 'orders', 'payment_method'):
        cursor.execute("ALTER TABLE orders ADD COLUMN payment_method TEXT")
    if not _column_exists(cursor, 'orders', 'delivery_area_id'):
        cursor.execute("ALTER TABLE orders ADD COLUMN delivery_area_id INTEGER")
    if not _column_exists(cursor, 'orders', 'delivery_fee'):
        cursor.execute("ALTER TABLE orders ADD COLUMN delivery_fee REAL NOT NULL DEFAULT 0")
    if not _column_exists(cursor, 'orders', 'subtotal'):
        cursor.execute("ALTER TABLE orders ADD COLUMN subtotal REAL")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS delivery_areas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        delivery_fee REAL NOT NULL DEFAULT 0,
        is_active INTEGER NOT NULL DEFAULT 1
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS rate_limit_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bucket TEXT NOT NULL,
        identifier TEXT NOT NULL,
        created_at REAL NOT NULL
    )
    """)

    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_rate_limit_lookup ON rate_limit_events (bucket, identifier, created_at)"
    )

    _ensure_default_categories(cursor)
    _ensure_default_delivery_areas(cursor)
    _ensure_store_settings(cursor)
    ensure_admin_user(conn)
    ensure_guest_user(conn)
    
    conn.commit()
    conn.close()
    print("Banco de dados inicializado com sucesso (Usuários, Produtos e Pedidos).")

# --- FUNÇÕES DE LÓGICA DE USUÁRIO ---

def cadastrar_usuario(nome, email, senha_pura, whatsapp=None, is_admin=0):
    conn = get_db()
    cursor = conn.cursor()
    senha_hashed = _hash_password(senha_pura)

    try:
        cursor.execute(
            "INSERT INTO users (nome, email, senha, whatsapp, is_admin) VALUES (?, ?, ?, ?, ?)",
            (nome, email, senha_hashed, whatsapp, is_admin),
        )
        conn.commit()
        print(f"Usuário {nome} cadastrado com sucesso!")
    except sqlite3.IntegrityError:
        print("Erro: Este e-mail já está cadastrado.")
    finally:
        conn.close()

def verificar_login(email, senha_digitada):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    usuario = cursor.fetchone()
    conn.close()

    if usuario:
        senha_banco_bytes = usuario['senha'].encode('utf-8')
        if bcrypt.checkpw(senha_digitada.encode('utf-8'), senha_banco_bytes):
            return usuario 
    return False

# --- FUNÇÕES DE PRODUTOS ---

def cadastrar_produto(nome, preco):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO products (nome, preco) VALUES (?, ?)", (nome, preco))
        conn.commit()
    finally:
        conn.close()

# --- TESTANDO O CÓDIGO ---

if __name__ == "__main__":
    init_db()