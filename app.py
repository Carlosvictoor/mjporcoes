import os
import secrets
import time
import uuid
from datetime import datetime, timedelta

from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.utils import secure_filename

from database import ADMIN_EMAIL, GUEST_EMAIL, init_db, get_db, cadastrar_usuario, verificar_login
from functools import wraps

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "devdelivery_secret")
app.permanent_session_lifetime = timedelta(days=30)
app.config['UPLOAD_FOLDER'] = os.path.join(app.static_folder, 'uploads')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.getenv("SESSION_COOKIE_SECURE", "1") == "1"
app.config['PREFERRED_URL_SCHEME'] = 'https'

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
FORCE_HTTPS = os.getenv("FORCE_HTTPS", "0") == "1"
RATE_LIMIT_RETENTION_SECONDS = int(os.getenv("RATE_LIMIT_RETENTION_SECONDS", "86400"))
CSRF_TTL_SECONDS = int(os.getenv("CSRF_TTL_SECONDS", "1800"))

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

init_db()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_uploaded_file(file_storage):
    if not file_storage or not file_storage.filename:
        return None
    if not allowed_file(file_storage.filename):
        return None

    extension = file_storage.filename.rsplit('.', 1)[1].lower()
    filename = secure_filename(file_storage.filename.rsplit('.', 1)[0]) or 'imagem'
    unique_name = f"{filename}-{uuid.uuid4().hex[:8]}.{extension}"
    save_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
    file_storage.save(save_path)
    return f"uploads/{unique_name}"

def get_store_settings():
    with get_db() as conn:
        settings = conn.execute("SELECT * FROM store_settings WHERE id = 1").fetchone()
    return settings

def get_categories():
    with get_db() as conn:
        categories = conn.execute(
            "SELECT * FROM categories ORDER BY display_order, name"
        ).fetchall()
    return categories

def get_delivery_areas(include_inactive=False):
    query = "SELECT * FROM delivery_areas"
    if not include_inactive:
        query += " WHERE is_active = 1"
    query += " ORDER BY name"

    with get_db() as conn:
        rows = conn.execute(query).fetchall()
    return rows

def get_products(include_inactive=False):
    query = """
        SELECT products.*, categories.name AS category_name, categories.display_order
        FROM products
        LEFT JOIN categories ON products.category_id = categories.id
    """
    params = []
    if not include_inactive:
        query += " WHERE products.is_active = 1"
    query += " ORDER BY COALESCE(categories.display_order, 999), products.nome"

    with get_db() as conn:
        products = conn.execute(query, params).fetchall()
    return products

def build_menu_sections(products, categories):
    sections = []
    products_by_category = {}

    for product in products:
        category_id = product['category_id'] or 0
        products_by_category.setdefault(category_id, []).append(product)

    for category in categories:
        category_products = products_by_category.pop(category['id'], [])
        if category_products:
            sections.append({
                'id': category['id'],
                'name': category['name'],
                'products': category_products,
            })

    uncategorized = products_by_category.pop(0, [])
    if uncategorized:
        sections.append({
            'id': 0,
            'name': 'Outros',
            'products': uncategorized,
        })

    return sections

def is_store_open():
    settings = get_store_settings()
    return bool(settings['is_open']) if settings else True

def format_datetime_br(value):
    if not value:
        return "-"

    parsed = None
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            parsed = datetime.strptime(str(value), fmt)
            break
        except ValueError:
            continue

    if not parsed:
        return str(value)

    return parsed.strftime("%d/%m/%Y %H:%M")

def payment_method_label(payment_method):
    labels = {
        'pix': 'Pix',
        'dinheiro': 'Dinheiro',
        'cartao_credito': 'Cartao de credito',
        'cartao_debito': 'Cartao de debito',
    }
    return labels.get(payment_method, payment_method or '-')

def build_payment_description(payment_method, needs_change=False, change_for=None):
    base = payment_method_label(payment_method)
    if payment_method != 'dinheiro':
        return base

    if needs_change and change_for is not None:
        return f"{base} (Troco para R$ {change_for:.2f})"
    return f"{base} (Sem troco)"

def get_guest_user_id(conn):
    guest = conn.execute(
        "SELECT id FROM users WHERE email = ?",
        (GUEST_EMAIL,),
    ).fetchone()
    return guest['id'] if guest else None

def get_client_identifier():
    forwarded_for = request.headers.get('X-Forwarded-For', '').strip()
    if forwarded_for:
        return forwarded_for.split(',')[0].strip()
    return request.remote_addr or 'unknown'

def is_request_secure():
    if request.is_secure:
        return True
    forwarded_proto = request.headers.get('X-Forwarded-Proto', '').lower()
    forwarded_ssl = request.headers.get('X-Forwarded-Ssl', '').lower()
    return forwarded_proto == 'https' or forwarded_ssl == 'on'

def is_rate_limited(bucket, identifier, limit, window_seconds):
    now = time.time()
    window_start = now - window_seconds
    with get_db() as conn:
        conn.execute(
            "DELETE FROM rate_limit_events WHERE created_at < ?",
            (now - RATE_LIMIT_RETENTION_SECONDS,),
        )
        count = conn.execute(
            """
            SELECT COUNT(*) FROM rate_limit_events
            WHERE bucket = ? AND identifier = ? AND created_at >= ?
            """,
            (bucket, identifier, window_start),
        ).fetchone()[0]
        conn.commit()
    return count >= limit

def register_rate_event(bucket, identifier):
    now = time.time()
    with get_db() as conn:
        conn.execute(
            "INSERT INTO rate_limit_events (bucket, identifier, created_at) VALUES (?, ?, ?)",
            (bucket, identifier, now),
        )
        conn.commit()

def clear_rate_events(bucket, identifier):
    with get_db() as conn:
        conn.execute(
            "DELETE FROM rate_limit_events WHERE bucket = ? AND identifier = ?",
            (bucket, identifier),
        )
        conn.commit()

def _prune_csrf_store():
    now = time.time()
    store = session.get('csrf_store', {})
    cleaned = {
        action: value
        for action, value in store.items()
        if isinstance(value, dict) and value.get('expires_at', 0) > now
    }
    if cleaned != store:
        session['csrf_store'] = cleaned
        session.modified = True
    return cleaned

def issue_csrf_token(action='global'):
    store = _prune_csrf_store()
    current = store.get(action)
    if not current:
        current = {
            'token': secrets.token_urlsafe(24),
            'expires_at': time.time() + CSRF_TTL_SECONDS,
        }
        store[action] = current
        session['csrf_store'] = store
        session.modified = True
    return current['token']

def consume_csrf_token(action, sent_token):
    if not sent_token:
        return False

    store = _prune_csrf_store()
    current = store.get(action)
    if not current:
        return False

    token = current.get('token')
    if not token:
        return False

    if not secrets.compare_digest(str(sent_token), str(token)):
        return False

    store.pop(action, None)
    session['csrf_store'] = store
    session.modified = True
    return True

def ensure_csrf_token():
    issue_csrf_token('global')

@app.context_processor
def inject_global_context():
    settings = get_store_settings()
    return {
        'store_settings': settings,
        'store_is_open': bool(settings['is_open']) if settings else True,
        'session_is_admin': bool(session.get('is_admin')),
        'csrf_token': issue_csrf_token('global'),
        'csrf_token_for': issue_csrf_token,
    }

@app.before_request
def keep_session_persistent():
    if FORCE_HTTPS and not is_request_secure():
        secure_url = request.url.replace('http://', 'https://', 1)
        return redirect(secure_url, code=301)

    ensure_csrf_token()

    if request.method == 'POST':
        action = request.form.get('csrf_action', 'global')
        sent_token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token', '')
        valid = consume_csrf_token(action, sent_token)
        if not valid and action != 'global':
            valid = consume_csrf_token('global', sent_token)

        if not valid:
            flash("Sessão expirada. Atualize a página e tente novamente.")
            return redirect(request.referrer or url_for('home'))

    if 'user_id' in session:
        session.permanent = True
        if 'is_admin' not in session:
            with get_db() as conn:
                user = conn.execute(
                    "SELECT is_admin, nome, email FROM users WHERE id = ?",
                    (session['user_id'],),
                ).fetchone()
            if user:
                session['is_admin'] = bool(user['is_admin'])
                session['user_nome'] = user['nome']
                session['user_email'] = user['email']

# =========================
# DECORATOR: PROTEÇÃO
# =========================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Por favor, faça login para acessar esta página.")
            return redirect(url_for('home')) # Redireciona para home onde está o modal
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Por favor, faça login para acessar esta página.")
            return redirect(url_for('home'))
        if not session.get('is_admin'):
            flash("Acesso restrito ao administrador.")
            return redirect(url_for('produtos'))
        return f(*args, **kwargs)
    return decorated_function

# =========================
# ROTAS DE AUTENTICAÇÃO
# =========================

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nome = request.form.get('nome')
        email = request.form.get('email')
        senha = request.form.get('senha')
        whatsapp = request.form.get('whatsapp')
        
        with get_db() as conn:
            user_exists = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        
        if user_exists:
            flash("Erro: Este e-mail já está cadastrado.")
        else:
            cadastrar_usuario(nome, email, senha, whatsapp=whatsapp)
            flash("Cadastro realizado com sucesso! Faça o login.")
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    if request.method == 'POST':
        client_id = get_client_identifier()
        if is_rate_limited('login', client_id, limit=6, window_seconds=300):
            flash("Muitas tentativas de login. Aguarde 5 minutos e tente novamente.")
            return redirect(url_for('login'))

        email = request.form.get('email')
        senha = request.form.get('senha')
        user = verificar_login(email, senha)
        
        if user:
            clear_rate_events('login', client_id)
            session.clear()
            session.permanent = True
            session['user_id'] = user['id']
            session['user_nome'] = user['nome']
            session['user_email'] = user['email']
            session['is_admin'] = bool(user['is_admin'])
            session['csrf_store'] = {}
            issue_csrf_token('global')
            
            if session['is_admin'] or email == ADMIN_EMAIL:
                return redirect(url_for('admin_dashboard'))
                
            return redirect(url_for('produtos'))
            
        register_rate_event('login', client_id)
        flash("E-mail ou senha incorretos.")
        return redirect(url_for('login'))

    return redirect(url_for('home'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# =========================
# PAINEL DO ADMINISTRADOR (ESTILO CHIQUE)
# =========================
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    with get_db() as conn:
        loja = conn.execute("SELECT * FROM store_settings WHERE id = 1").fetchone()
        period_start = (
            loja['last_financial_reset']
            if loja and loja['last_financial_reset']
            else '1970-01-01 00:00:00'
        )

        pedidos = conn.execute("""
            SELECT
                orders.*,
                COALESCE(NULLIF(orders.customer_name, ''), users.nome, 'Cliente') AS cliente,
                COALESCE(NULLIF(orders.customer_phone, ''), users.whatsapp, '-') AS cliente_telefone,
                COALESCE(NULLIF(orders.customer_address, ''), '-') AS cliente_endereco,
                COALESCE(NULLIF(orders.customer_neighborhood, ''), '-') AS cliente_bairro,
                COALESCE(orders.delivery_fee, 0) AS taxa_entrega,
                COALESCE(NULLIF(orders.payment_method, ''), '-') AS forma_pagamento
            FROM orders 
            LEFT JOIN users ON orders.user_id = users.id
            ORDER BY orders.data DESC
        """).fetchall()

        financial_cycle = conn.execute(
            """
            SELECT
                COUNT(*) AS orders_count,
                COALESCE(SUM(total), 0) AS gross_revenue,
                COALESCE(SUM(CASE WHEN status = 'Entregue' THEN total ELSE 0 END), 0) AS delivered_revenue,
                COALESCE(SUM(CASE WHEN status IN ('Pendente', 'Em preparo', 'A caminho') THEN total ELSE 0 END), 0) AS open_revenue,
                COALESCE(SUM(CASE WHEN status = 'Cancelado' THEN total ELSE 0 END), 0) AS canceled_revenue,
                SUM(CASE WHEN status = 'Entregue' THEN 1 ELSE 0 END) AS delivered_orders,
                SUM(CASE WHEN status = 'Cancelado' THEN 1 ELSE 0 END) AS canceled_orders,
                SUM(CASE WHEN status = 'Pendente' THEN 1 ELSE 0 END) AS pending_orders,
                SUM(CASE WHEN status = 'Em preparo' THEN 1 ELSE 0 END) AS in_preparation_orders,
                SUM(CASE WHEN status = 'A caminho' THEN 1 ELSE 0 END) AS on_the_way_orders
            FROM orders
            WHERE data >= ?
            """,
            (period_start,),
        ).fetchone()

        financial_history = conn.execute(
            """
            SELECT fc.*, users.nome AS closed_by_name
            FROM financial_closures fc
            LEFT JOIN users ON users.id = fc.closed_by_user_id
            ORDER BY fc.period_end DESC
            LIMIT 20
            """
        ).fetchall()

        financial_history_view = []
        for closure in financial_history:
            closure_view = dict(closure)
            closure_view['period_start_br'] = format_datetime_br(closure['period_start'])
            closure_view['period_end_br'] = format_datetime_br(closure['period_end'])
            financial_history_view.append(closure_view)

        total_pedidos = len(pedidos)
        faturamento = financial_cycle['gross_revenue'] if financial_cycle else 0
        pedidos_pendentes = sum(1 for pedido in pedidos if pedido['status'] == 'Pendente')
        categories = conn.execute(
            "SELECT * FROM categories ORDER BY display_order, name"
        ).fetchall()
        delivery_areas = conn.execute(
            "SELECT * FROM delivery_areas ORDER BY name"
        ).fetchall()
        produtos = conn.execute(
            """
            SELECT products.*, categories.name AS category_name
            FROM products
            LEFT JOIN categories ON products.category_id = categories.id
            ORDER BY products.id DESC
            """
        ).fetchall()

    return render_template('admin_dashboard.html', 
                           pedidos=pedidos, 
                           total_pedidos=total_pedidos, 
                           pedidos_pendentes=pedidos_pendentes,
                           faturamento=round(faturamento, 2),
                           financial_period_start=period_start,
                           financial_period_start_br=format_datetime_br(period_start),
                           financial_cycle=financial_cycle,
                           financial_history=financial_history_view,
                           categorias=categories,
                           delivery_areas=delivery_areas,
                           produtos=produtos,
                           loja=loja)

@app.route('/atualizar_status/<int:pedido_id>/<status>')
@admin_required
def atualizar_status(pedido_id, status):
    allowed_status = {'Pendente', 'Em preparo', 'A caminho', 'Entregue', 'Cancelado'}
    if status not in allowed_status:
        flash("Status inválido.")
        return redirect(url_for('admin_dashboard'))

    with get_db() as conn:
        conn.execute("UPDATE orders SET status = ? WHERE id = ?", (status, pedido_id))
        conn.commit()
    
    flash(f"Pedido #{pedido_id} atualizado!")
    return redirect(url_for('admin_dashboard'))

# =========================
# GESTÃO DE PRODUTOS & CARDÁPIO
# =========================

@app.route('/produtos')
def produtos():
    categories = get_categories()
    products = get_products()
    featured_products = [product for product in products if product['is_featured']][:3] or list(products[:3])
    menu_sections = build_menu_sections(products, categories)
    return render_template(
        'produtos.html',
        produtos=products,
        featured_products=featured_products,
        menu_sections=menu_sections,
        categories=categories,
    )

@app.route('/add_produto', methods=['GET', 'POST'])
@admin_required
def add_produto():
    if request.method == 'POST':
        nome = request.form.get('nome', '').strip()
        preco = request.form.get('preco', '0').strip()
        descricao = request.form.get('descricao', '').strip()
        category_id = request.form.get('category_id') or None
        is_featured = 1 if request.form.get('is_featured') else 0
        is_active = 1 if request.form.get('is_active') else 0
        image_path = save_uploaded_file(request.files.get('imagem'))

        if not nome:
            flash("Informe o nome do produto.")
            return redirect(url_for('add_produto'))

        with get_db() as conn:
            conn.execute(
                """
                INSERT INTO products (nome, preco, descricao, image_path, category_id, is_featured, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (nome, preco, descricao, image_path, category_id, is_featured, is_active),
            )
            conn.commit()
        flash("Produto adicionado com sucesso!")
        return redirect(url_for('produtos'))

    categories = get_categories()
    products = get_products(include_inactive=True)
    editing_id = request.args.get('edit_id', type=int)
    editing_product = None

    if editing_id:
        with get_db() as conn:
            editing_product = conn.execute(
                "SELECT * FROM products WHERE id = ?",
                (editing_id,),
            ).fetchone()

    return render_template(
        'add_produto.html',
        categorias=categories,
        produtos=products,
        editing_product=editing_product,
    )

@app.route('/admin/loja', methods=['POST'])
@admin_required
def atualizar_loja():
    nome = request.form.get('store_name', 'MJ Porções').strip() or 'MJ Porções'
    tagline = request.form.get('tagline', '').strip() or 'Porções caprichadas, entrega rápida e atendimento digital.'
    opening_hours = request.form.get('opening_hours', '').strip() or 'Todos os dias, das 18h às 23h'
    delivery_mode = request.form.get('delivery_mode', '').strip() or 'Entrega e retirada'
    store_status = request.form.get('store_status', '').strip().lower()
    if store_status in {'open', 'closed'}:
        is_open = 1 if store_status == 'open' else 0
    else:
        is_open = 1 if request.form.get('is_open') else 0

    with get_db() as conn:
        current = conn.execute("SELECT * FROM store_settings WHERE id = 1").fetchone()
        banner_image = current['banner_image'] if current else None
        profile_image = current['profile_image'] if current else None
        was_open = bool(current['is_open']) if current else True
        period_start = (
            current['last_financial_reset']
            if current and current['last_financial_reset']
            else '1970-01-01 00:00:00'
        )

        new_banner = save_uploaded_file(request.files.get('banner_image'))
        new_profile = save_uploaded_file(request.files.get('profile_image'))

        if new_banner:
            banner_image = new_banner
        if new_profile:
            profile_image = new_profile

        conn.execute(
            """
            UPDATE store_settings
            SET store_name = ?, tagline = ?, banner_image = ?, profile_image = ?,
                opening_hours = ?, is_open = ?, delivery_mode = ?
            WHERE id = 1
            """,
            (nome, tagline, banner_image, profile_image, opening_hours, is_open, delivery_mode),
        )

        if was_open and not bool(is_open):
            cycle_snapshot = conn.execute(
                """
                SELECT
                    COUNT(*) AS orders_count,
                    COALESCE(SUM(total), 0) AS gross_revenue,
                    COALESCE(SUM(CASE WHEN status = 'Entregue' THEN total ELSE 0 END), 0) AS delivered_revenue,
                    COALESCE(SUM(CASE WHEN status IN ('Pendente', 'Em preparo', 'A caminho') THEN total ELSE 0 END), 0) AS open_revenue,
                    COALESCE(SUM(CASE WHEN status = 'Cancelado' THEN total ELSE 0 END), 0) AS canceled_revenue,
                    SUM(CASE WHEN status = 'Entregue' THEN 1 ELSE 0 END) AS delivered_orders,
                    SUM(CASE WHEN status = 'Cancelado' THEN 1 ELSE 0 END) AS canceled_orders,
                    SUM(CASE WHEN status = 'Pendente' THEN 1 ELSE 0 END) AS pending_orders,
                    SUM(CASE WHEN status = 'Em preparo' THEN 1 ELSE 0 END) AS in_preparation_orders,
                    SUM(CASE WHEN status = 'A caminho' THEN 1 ELSE 0 END) AS on_the_way_orders
                FROM orders
                WHERE data >= ?
                """,
                (period_start,),
            ).fetchone()

            conn.execute(
                """
                INSERT INTO financial_closures (
                    period_start,
                    period_end,
                    orders_count,
                    gross_revenue,
                    delivered_revenue,
                    open_revenue,
                    canceled_revenue,
                    delivered_orders,
                    canceled_orders,
                    pending_orders,
                    in_preparation_orders,
                    on_the_way_orders,
                    closed_by_user_id
                ) VALUES (?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    period_start,
                    cycle_snapshot['orders_count'] or 0,
                    cycle_snapshot['gross_revenue'] or 0,
                    cycle_snapshot['delivered_revenue'] or 0,
                    cycle_snapshot['open_revenue'] or 0,
                    cycle_snapshot['canceled_revenue'] or 0,
                    cycle_snapshot['delivered_orders'] or 0,
                    cycle_snapshot['canceled_orders'] or 0,
                    cycle_snapshot['pending_orders'] or 0,
                    cycle_snapshot['in_preparation_orders'] or 0,
                    cycle_snapshot['on_the_way_orders'] or 0,
                    session.get('user_id'),
                ),
            )
            conn.execute(
                "UPDATE store_settings SET last_financial_reset = CURRENT_TIMESTAMP WHERE id = 1"
            )

        conn.commit()

    if was_open and not bool(is_open):
        flash("Loja fechada: financeiro do ciclo foi salvo no histórico e resetado para o próximo período.")
    else:
        flash("Configurações da loja atualizadas.")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/categorias', methods=['POST'])
@admin_required
def adicionar_categoria():
    name = request.form.get('name', '').strip()
    display_order = request.form.get('display_order', type=int) or 0

    if not name:
        flash("Informe o nome da categoria.")
        return redirect(url_for('admin_dashboard'))

    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO categories (name, display_order) VALUES (?, ?)",
                (name, display_order),
            )
            conn.commit()
        flash("Categoria criada com sucesso.")
    except Exception:
        flash("Não foi possível criar a categoria. Verifique se ela já existe.")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/categorias/<int:category_id>/delete', methods=['POST'])
@admin_required
def excluir_categoria(category_id):
    with get_db() as conn:
        total_products = conn.execute(
            "SELECT COUNT(*) FROM products WHERE category_id = ?",
            (category_id,),
        ).fetchone()[0]
        if total_products:
            flash("Remova ou troque os produtos dessa categoria antes de excluí-la.")
            return redirect(url_for('admin_dashboard'))

        conn.execute("DELETE FROM categories WHERE id = ?", (category_id,))
        conn.commit()

    flash("Categoria removida com sucesso.")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/bairros', methods=['POST'])
@admin_required
def adicionar_bairro_entrega():
    name = request.form.get('name', '').strip()
    delivery_fee = request.form.get('delivery_fee', '0').strip()

    if not name:
        flash("Informe o nome do bairro.")
        return redirect(url_for('admin_dashboard'))

    try:
        fee_value = float(delivery_fee.replace(',', '.'))
        if fee_value < 0:
            raise ValueError()
    except ValueError:
        flash("Informe uma taxa de entrega valida.")
        return redirect(url_for('admin_dashboard'))

    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO delivery_areas (name, delivery_fee, is_active) VALUES (?, ?, 1)",
                (name, fee_value),
            )
            conn.commit()
        flash("Bairro de entrega cadastrado com sucesso.")
    except Exception:
        flash("Nao foi possivel cadastrar o bairro. Verifique se ele ja existe.")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/bairros/<int:area_id>/delete', methods=['POST'])
@admin_required
def excluir_bairro_entrega(area_id):
    with get_db() as conn:
        conn.execute("DELETE FROM delivery_areas WHERE id = ?", (area_id,))
        conn.commit()
    flash("Bairro removido com sucesso.")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/bairros/<int:area_id>/editar', methods=['POST'])
@admin_required
def editar_bairro_entrega(area_id):
    name = request.form.get('name', '').strip()
    delivery_fee = request.form.get('delivery_fee', '0').strip()

    if not name:
        flash("Informe o nome do bairro.")
        return redirect(url_for('admin_dashboard'))

    try:
        fee_value = float(delivery_fee.replace(',', '.'))
        if fee_value < 0:
            raise ValueError()
    except ValueError:
        flash("Informe uma taxa de entrega valida.")
        return redirect(url_for('admin_dashboard'))

    with get_db() as conn:
        exists = conn.execute(
            "SELECT id FROM delivery_areas WHERE id = ?",
            (area_id,),
        ).fetchone()
        if not exists:
            flash("Bairro nao encontrado.")
            return redirect(url_for('admin_dashboard'))

        try:
            conn.execute(
                "UPDATE delivery_areas SET name = ?, delivery_fee = ? WHERE id = ?",
                (name, fee_value, area_id),
            )
            conn.commit()
        except Exception:
            flash("Nao foi possivel atualizar. Verifique se o nome do bairro ja existe.")
            return redirect(url_for('admin_dashboard'))

    flash("Bairro e taxa atualizados com sucesso.")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/produtos/<int:produto_id>/editar', methods=['POST'])
@admin_required
def editar_produto(produto_id):
    nome = request.form.get('nome', '').strip()
    preco = request.form.get('preco', '0').strip()
    descricao = request.form.get('descricao', '').strip()
    category_id = request.form.get('category_id') or None
    is_featured = 1 if request.form.get('is_featured') else 0
    is_active = 1 if request.form.get('is_active') else 0

    with get_db() as conn:
        current = conn.execute("SELECT * FROM products WHERE id = ?", (produto_id,)).fetchone()
        if not current:
            flash("Produto não encontrado.")
            return redirect(url_for('add_produto'))

        image_path = current['image_path']
        new_image = save_uploaded_file(request.files.get('imagem'))
        if new_image:
            image_path = new_image

        conn.execute(
            """
            UPDATE products
            SET nome = ?, preco = ?, descricao = ?, image_path = ?, category_id = ?,
                is_featured = ?, is_active = ?
            WHERE id = ?
            """,
            (nome, preco, descricao, image_path, category_id, is_featured, is_active, produto_id),
        )
        conn.commit()

    flash("Produto atualizado com sucesso.")
    return redirect(url_for('add_produto'))

@app.route('/admin/produtos/<int:produto_id>/delete', methods=['POST'])
@admin_required
def excluir_produto(produto_id):
    with get_db() as conn:
        conn.execute("DELETE FROM products WHERE id = ?", (produto_id,))
        conn.commit()

    flash("Produto removido com sucesso.")
    return redirect(url_for('add_produto'))

# =========================
# CARRINHO & PEDIDOS
# =========================

@app.route('/add_carrinho/<int:produto_id>')
def add_carrinho(produto_id):
    if not is_store_open() and not session.get('is_admin'):
        flash("A loja está fechada no momento.")
        return redirect(url_for('produtos'))

    with get_db() as conn:
        produto = conn.execute("SELECT * FROM products WHERE id = ?", (produto_id,)).fetchone()

    if not produto:
        flash("Produto não encontrado")
        return redirect(url_for('produtos'))

    if 'carrinho' not in session:
        session['carrinho'] = {}

    carrinho = session['carrinho']
    pid = str(produto_id)

    if pid in carrinho:
        carrinho[pid]['quantidade'] += 1
    else:
        carrinho[pid] = {'nome': produto['nome'], 'preco': produto['preco'], 'quantidade': 1}

    session.modified = True
    flash(f"{produto['nome']} adicionado ao carrinho!")
    return redirect(url_for('produtos'))

@app.route('/carrinho')
def carrinho():
    carrinho_dict = session.get('carrinho', {})
    total = sum(item['preco'] * item['quantidade'] for item in carrinho_dict.values())
    return render_template('carrinho.html', carrinho=carrinho_dict, total=round(total, 2))

@app.route('/remover_item/<int:produto_id>')
def remover_item(produto_id):
    carrinho_dict = session.get('carrinho', {})
    pid = str(produto_id)

    if pid not in carrinho_dict:
        flash("Item não encontrado no carrinho.")
        return redirect(url_for('carrinho'))

    if carrinho_dict[pid]['quantidade'] > 1:
        carrinho_dict[pid]['quantidade'] -= 1
    else:
        carrinho_dict.pop(pid)

    session['carrinho'] = carrinho_dict
    session.modified = True
    flash("Item atualizado no carrinho.")
    return redirect(url_for('carrinho'))

@app.route('/limpar_carrinho')
def limpar_carrinho():
    session['carrinho'] = {}
    session.modified = True
    flash("Carrinho esvaziado com sucesso.")
    return redirect(url_for('carrinho'))

@app.route('/finalizar_pedido', methods=['GET', 'POST'])
def finalizar_pedido():
    if not is_store_open() and not session.get('is_admin'):
        flash("A loja está fechada no momento. Aguarde a reabertura para concluir pedidos.")
        return redirect(url_for('produtos'))

    carrinho = session.get('carrinho', {})
    if not carrinho:
        flash("Seu carrinho está vazio!")
        return redirect(url_for('produtos'))

    subtotal = sum(item['preco'] * item['quantidade'] for item in carrinho.values())
    delivery_areas = get_delivery_areas()

    if request.method == 'GET':
        customer_name = session.get('user_nome', '') if session.get('user_id') else ''
        customer_phone = ''
        if session.get('user_id'):
            with get_db() as conn:
                user = conn.execute(
                    "SELECT whatsapp FROM users WHERE id = ?",
                    (session['user_id'],),
                ).fetchone()
                customer_phone = user['whatsapp'] if user and user['whatsapp'] else ''

        return render_template(
            'finalizar_pedido.html',
            carrinho=carrinho,
            subtotal=round(subtotal, 2),
            delivery_areas=delivery_areas,
            customer_name=customer_name,
            customer_phone=customer_phone,
            customer_address='',
            customer_neighborhood='',
            selected_delivery_area_id='',
            delivery_fee=0,
            total=round(subtotal, 2),
            payment_method='',
            needs_change=False,
            change_for='',
        )

    client_id = get_client_identifier()
    if is_rate_limited('checkout', client_id, limit=10, window_seconds=600):
        flash("Muitas tentativas de envio de pedido. Aguarde alguns minutos e tente novamente.")
        return redirect(url_for('carrinho'))
    register_rate_event('checkout', client_id)

    customer_name = request.form.get('customer_name', '').strip()
    customer_phone = request.form.get('customer_phone', '').strip()
    customer_address = request.form.get('customer_address', '').strip()
    selected_delivery_area_id = request.form.get('delivery_area_id', '').strip()
    payment_method = request.form.get('payment_method', '').strip()
    needs_change = bool(request.form.get('needs_change'))
    change_for_raw = request.form.get('change_for', '').strip()

    change_for = None
    if payment_method == 'dinheiro' and needs_change:
        try:
            change_for = float(change_for_raw.replace(',', '.'))
        except ValueError:
            change_for = None

    selected_area = None
    if selected_delivery_area_id:
        try:
            area_id = int(selected_delivery_area_id)
        except ValueError:
            area_id = None
        if area_id is not None:
            with get_db() as conn:
                selected_area = conn.execute(
                    "SELECT * FROM delivery_areas WHERE id = ? AND is_active = 1",
                    (area_id,),
                ).fetchone()

    if not customer_name or not customer_phone or not customer_address or not selected_area or not payment_method:
        flash("Preencha Nome, Telefone, Endereco, Bairro e Forma de Pagamento.")
        return render_template(
            'finalizar_pedido.html',
            carrinho=carrinho,
            subtotal=round(subtotal, 2),
            delivery_areas=delivery_areas,
            customer_name=customer_name,
            customer_phone=customer_phone,
            customer_address=customer_address,
            customer_neighborhood=(selected_area['name'] if selected_area else ''),
            selected_delivery_area_id=selected_delivery_area_id,
            delivery_fee=(selected_area['delivery_fee'] if selected_area else 0),
            total=round(subtotal + (selected_area['delivery_fee'] if selected_area else 0), 2),
            payment_method=payment_method,
            needs_change=needs_change,
            change_for=change_for_raw,
        )

    customer_neighborhood = selected_area['name']
    delivery_fee = float(selected_area['delivery_fee'])
    total = subtotal + delivery_fee

    if payment_method == 'dinheiro' and needs_change and (change_for is None or change_for <= 0):
        flash("Informe um valor valido para troco.")
        return render_template(
            'finalizar_pedido.html',
            carrinho=carrinho,
            subtotal=round(subtotal, 2),
            delivery_areas=delivery_areas,
            customer_name=customer_name,
            customer_phone=customer_phone,
            customer_address=customer_address,
            customer_neighborhood=customer_neighborhood,
            selected_delivery_area_id=selected_delivery_area_id,
            delivery_fee=delivery_fee,
            total=round(total, 2),
            payment_method=payment_method,
            needs_change=needs_change,
            change_for=change_for_raw,
        )

    if payment_method == 'dinheiro' and needs_change and change_for < total:
        flash("O valor para troco deve ser maior ou igual ao total do pedido.")
        return render_template(
            'finalizar_pedido.html',
            carrinho=carrinho,
            subtotal=round(subtotal, 2),
            delivery_areas=delivery_areas,
            customer_name=customer_name,
            customer_phone=customer_phone,
            customer_address=customer_address,
            customer_neighborhood=customer_neighborhood,
            selected_delivery_area_id=selected_delivery_area_id,
            delivery_fee=delivery_fee,
            total=round(total, 2),
            payment_method=payment_method,
            needs_change=needs_change,
            change_for=change_for_raw,
        )

    try:
        with get_db() as conn:
            user_id = session.get('user_id')
            if not user_id:
                user_id = get_guest_user_id(conn)

            conn.execute(
                """
                INSERT INTO orders (
                    user_id, customer_name, customer_phone, customer_address, customer_neighborhood,
                    delivery_area_id, delivery_fee, subtotal,
                    needs_change, change_for, payment_method, total, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    customer_name,
                    customer_phone,
                    customer_address,
                    customer_neighborhood,
                    selected_area['id'],
                    delivery_fee,
                    subtotal,
                    1 if needs_change else 0,
                    change_for,
                    build_payment_description(payment_method, needs_change, change_for),
                    total,
                    'Pendente',
                ),
            )
            conn.commit()

        session['carrinho'] = {}
        session.modified = True
        flash("Pedido enviado com sucesso!")

        if session.get('user_id'):
            return redirect(url_for('meus_pedidos'))
        return redirect(url_for('produtos'))
    except Exception:
        flash("Erro ao processar pedido.")
        return redirect(url_for('carrinho'))

@app.route('/meus_pedidos')
@login_required
def meus_pedidos():
    with get_db() as conn:
        pedidos = conn.execute("SELECT * FROM orders WHERE user_id = ? ORDER BY data DESC", 
                               (session['user_id'],)).fetchall()
    return render_template('pedidos.html', pedidos=pedidos)

if __name__ == '__main__':
    app.run(debug=True)