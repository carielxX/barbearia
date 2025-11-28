import os
import io
import csv
import re
import logging
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, jsonify, 
    session, redirect, url_for, send_file, flash, g
)
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import event, Index
from sqlalchemy.orm import validates

# ============================================================
# CONFIGURAÇÃO
# ============================================================

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "barblab.db")

app = Flask(__name__, template_folder="templates", static_folder="static")

# Configurações
app.config.update(
    SQLALCHEMY_DATABASE_URI=f"sqlite:///{DB_PATH}",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_ENGINE_OPTIONS={
        "pool_pre_ping": True,
        "pool_recycle": 300,
    },
    SECRET_KEY=os.getenv("SECRET_KEY", "troque_em_producao_" + os.urandom(16).hex()),
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    SESSION_COOKIE_SECURE=os.getenv("FLASK_ENV") == "production",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB max upload
)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("barblab")

# Database
db = SQLAlchemy(app)
migrate = Migrate(app, db)


# ============================================================
# ENUMS E CONSTANTES
# ============================================================

class StatusAgendamento:
    PENDENTE = "pendente"
    CONFIRMADO = "confirmado"
    CONCLUIDO = "concluido"
    CANCELADO = "cancelado"

SERVICOS_DISPONIVEIS = [
    {"id": "corte", "nome": "Corte de Cabelo", "preco": 35.00, "duracao": 30},
    {"id": "barba", "nome": "Barba", "preco": 25.00, "duracao": 20},
    {"id": "corte_barba", "nome": "Corte + Barba", "preco": 55.00, "duracao": 50},
    {"id": "sobrancelha", "nome": "Sobrancelha", "preco": 15.00, "duracao": 10},
    {"id": "pigmentacao", "nome": "Pigmentação", "preco": 80.00, "duracao": 60},
]

BARBEIROS = [
    {"id": "joao", "nome": "João Silva"},
    {"id": "pedro", "nome": "Pedro Santos"},
    {"id": "carlos", "nome": "Carlos Oliveira"},
]

HORARIOS_FUNCIONAMENTO = {
    "inicio": "09:00",
    "fim": "19:00",
    "intervalo": 30,  # minutos
    "dias_semana": [0, 1, 2, 3, 4, 5],  # seg a sab
}


# ============================================================
# MODELS
# ============================================================

class TimestampMixin:
    """Mixin para adicionar timestamps automáticos"""
    criado_em = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    atualizado_em = db.Column(
        db.DateTime, 
        default=datetime.utcnow, 
        onupdate=datetime.utcnow,
        nullable=False
    )


class Cliente(TimestampMixin, db.Model):
    __tablename__ = 'clientes'
    
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(200), nullable=False)
    cpf = db.Column(db.String(11), unique=True, nullable=False, index=True)
    email = db.Column(db.String(200), unique=True, index=True)
    telefone = db.Column(db.String(11))
    cep = db.Column(db.String(8))
    endereco = db.Column(db.String(300))
    numero = db.Column(db.String(20))
    complemento = db.Column(db.String(100))
    observacoes = db.Column(db.Text)
    password_hash = db.Column(db.String(300), nullable=False)
    ativo = db.Column(db.Boolean, default=True, nullable=False)
    email_verificado = db.Column(db.Boolean, default=False)
    ultimo_login = db.Column(db.DateTime)
    tentativas_login = db.Column(db.Integer, default=0)
    bloqueado_ate = db.Column(db.DateTime)
    
    # Relacionamentos
    agendamentos = db.relationship(
        'Agendamento', 
        backref='cliente', 
        lazy='dynamic',
        cascade='all, delete-orphan'
    )
    
    # Índices compostos
    __table_args__ = (
        Index('idx_cliente_nome_cpf', 'nome', 'cpf'),
    )
    
    def set_password(self, password):
        """Hash da senha com salt"""
        self.password_hash = generate_password_hash(
            password, 
            method='pbkdf2:sha256:260000'
        )
    
    def check_password(self, password):
        """Verifica senha"""
        return check_password_hash(self.password_hash, password)
    
    def esta_bloqueado(self):
        """Verifica se conta está bloqueada"""
        if self.bloqueado_ate and self.bloqueado_ate > datetime.utcnow():
            return True
        return False
    
    def registrar_tentativa_falha(self):
        """Registra tentativa de login falha"""
        self.tentativas_login += 1
        if self.tentativas_login >= 5:
            self.bloqueado_ate = datetime.utcnow() + timedelta(minutes=15)
        db.session.commit()
    
    def resetar_tentativas(self):
        """Reseta contador de tentativas"""
        self.tentativas_login = 0
        self.bloqueado_ate = None
        self.ultimo_login = datetime.utcnow()
        db.session.commit()
    
    @validates('email')
    def validate_email(self, key, email):
        if email:
            email = email.lower().strip()
            if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
                raise ValueError("E-mail inválido")
        return email
    
    @validates('cpf')
    def validate_cpf(self, key, cpf):
        cpf = only_digits(cpf)
        if not valida_cpf(cpf):
            raise ValueError("CPF inválido")
        return cpf
    
    @validates('telefone')
    def validate_telefone(self, key, telefone):
        if telefone:
            telefone = only_digits(telefone)
            if len(telefone) not in [10, 11]:
                raise ValueError("Telefone inválido")
        return telefone
    
    def to_dict(self, include_sensitive=False):
        """Serializa para dicionário"""
        data = {
            "id": self.id,
            "nome": self.nome,
            "cpf": self.cpf_formatado,
            "email": self.email,
            "telefone": self.telefone_formatado,
            "ativo": self.ativo,
            "criado_em": self.criado_em.isoformat() if self.criado_em else None,
        }
        if include_sensitive:
            data.update({
                "cep": self.cep,
                "endereco": self.endereco,
                "numero": self.numero,
                "complemento": self.complemento,
                "observacoes": self.observacoes,
            })
        return data
    
    @property
    def cpf_formatado(self):
        """Retorna CPF formatado"""
        if self.cpf and len(self.cpf) == 11:
            return f"{self.cpf[:3]}.{self.cpf[3:6]}.{self.cpf[6:9]}-{self.cpf[9:]}"
        return self.cpf
    
    @property
    def telefone_formatado(self):
        """Retorna telefone formatado"""
        if self.telefone:
            if len(self.telefone) == 11:
                return f"({self.telefone[:2]}) {self.telefone[2:7]}-{self.telefone[7:]}"
            elif len(self.telefone) == 10:
                return f"({self.telefone[:2]}) {self.telefone[2:6]}-{self.telefone[6:]}"
        return self.telefone


class Agendamento(TimestampMixin, db.Model):
    __tablename__ = 'agendamentos'
    
    id = db.Column(db.Integer, primary_key=True)
    cliente_id = db.Column(
        db.Integer, 
        db.ForeignKey('clientes.id', ondelete='CASCADE'), 
        nullable=False,
        index=True
    )
    servico = db.Column(db.String(50), nullable=False)
    barbeiro = db.Column(db.String(50), nullable=False)
    data = db.Column(db.Date, nullable=False, index=True)
    horario = db.Column(db.Time, nullable=False)
    status = db.Column(
        db.String(20), 
        default=StatusAgendamento.PENDENTE,
        nullable=False,
        index=True
    )
    preco = db.Column(db.Numeric(10, 2))
    duracao_minutos = db.Column(db.Integer)
    observacoes = db.Column(db.Text)
    cancelado_em = db.Column(db.DateTime)
    motivo_cancelamento = db.Column(db.String(200))
    
    # Índices compostos
    __table_args__ = (
        Index('idx_agendamento_data_horario', 'data', 'horario'),
        Index('idx_agendamento_barbeiro_data', 'barbeiro', 'data'),
    )
    
    def to_dict(self):
        """Serializa para dicionário"""
        return {
            "id": self.id,
            "cliente_id": self.cliente_id,
            "cliente_nome": self.cliente.nome if self.cliente else None,
            "servico": self.servico,
            "servico_nome": self.servico_info.get("nome") if self.servico_info else self.servico,
            "barbeiro": self.barbeiro,
            "barbeiro_nome": self.barbeiro_info.get("nome") if self.barbeiro_info else self.barbeiro,
            "data": self.data.isoformat() if self.data else None,
            "horario": self.horario.strftime("%H:%M") if self.horario else None,
            "status": self.status,
            "preco": float(self.preco) if self.preco else None,
            "duracao_minutos": self.duracao_minutos,
            "criado_em": self.criado_em.isoformat() if self.criado_em else None,
        }
    
    @property
    def servico_info(self):
        """Retorna informações do serviço"""
        return next((s for s in SERVICOS_DISPONIVEIS if s["id"] == self.servico), None)
    
    @property
    def barbeiro_info(self):
        """Retorna informações do barbeiro"""
        return next((b for b in BARBEIROS if b["id"] == self.barbeiro), None)
    
    @property
    def pode_cancelar(self):
        """Verifica se pode cancelar (até 2h antes)"""
        if self.status == StatusAgendamento.CANCELADO:
            return False
        agora = datetime.utcnow()
        data_hora = datetime.combine(self.data, self.horario)
        return data_hora - agora > timedelta(hours=2)


class Admin(TimestampMixin, db.Model):
    __tablename__ = 'admins'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(200), unique=True)
    password_hash = db.Column(db.String(300), nullable=False)
    nome = db.Column(db.String(200))
    ativo = db.Column(db.Boolean, default=True)
    ultimo_login = db.Column(db.DateTime)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(
            password, 
            method='pbkdf2:sha256:260000'
        )
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class AuditLog(db.Model):
    """Log de auditoria para ações importantes"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    user_type = db.Column(db.String(20))  # 'cliente', 'admin'
    user_id = db.Column(db.Integer)
    action = db.Column(db.String(50), nullable=False)
    resource = db.Column(db.String(50))
    resource_id = db.Column(db.Integer)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(300))


# ============================================================
# FUNÇÕES UTILITÁRIAS
# ============================================================

def only_digits(s):
    """Remove tudo exceto dígitos"""
    return re.sub(r'\D', '', s or '')


def valida_cpf(cpf):
    """Valida CPF com algoritmo oficial"""
    cpf = only_digits(cpf)
    
    if len(cpf) != 11:
        return False
    
    # CPFs inválidos conhecidos
    if cpf == cpf[0] * 11:
        return False
    
    # Primeiro dígito verificador
    soma = sum(int(cpf[i]) * (10 - i) for i in range(9))
    resto = (soma * 10) % 11
    if resto == 10:
        resto = 0
    if resto != int(cpf[9]):
        return False
    
    # Segundo dígito verificador
    soma = sum(int(cpf[i]) * (11 - i) for i in range(10))
    resto = (soma * 10) % 11
    if resto == 10:
        resto = 0
    
    return resto == int(cpf[10])


def valida_email(email):
    """Valida formato de e-mail"""
    if not email:
        return True
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w{2,}$'
    return bool(re.match(pattern, email.lower().strip()))


def valida_telefone(telefone):
    """Valida telefone brasileiro"""
    if not telefone:
        return True
    telefone = only_digits(telefone)
    return len(telefone) in [10, 11]


def valida_cep(cep):
    """Valida CEP brasileiro"""
    if not cep:
        return True
    cep = only_digits(cep)
    return len(cep) == 8


def formata_cpf(cpf):
    """Formata CPF: 000.000.000-00"""
    cpf = only_digits(cpf)
    if len(cpf) == 11:
        return f"{cpf[:3]}.{cpf[3:6]}.{cpf[6:9]}-{cpf[9:]}"
    return cpf


def formata_telefone(telefone):
    """Formata telefone: (00) 00000-0000"""
    telefone = only_digits(telefone)
    if len(telefone) == 11:
        return f"({telefone[:2]}) {telefone[2:7]}-{telefone[7:]}"
    elif len(telefone) == 10:
        return f"({telefone[:2]}) {telefone[2:6]}-{telefone[6:]}"
    return telefone


def formata_cep(cep):
    """Formata CEP: 00000-000"""
    cep = only_digits(cep)
    if len(cep) == 8:
        return f"{cep[:5]}-{cep[5:]}"
    return cep


def log_audit(action, resource=None, resource_id=None, details=None):
    """Registra ação no log de auditoria"""
    try:
        user_type = None
        user_id = None
        
        if session.get('admin_id'):
            user_type = 'admin'
            user_id = session.get('admin_id')
        elif session.get('client_id'):
            user_type = 'cliente'
            user_id = session.get('client_id')
        
        log = AuditLog(
            user_type=user_type,
            user_id=user_id,
            action=action,
            resource=resource,
            resource_id=resource_id,
            details=details,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string[:300] if request.user_agent else None
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        logger.error(f"Erro ao registrar audit log: {e}")


# ============================================================
# DECORATORS
# ============================================================

def login_required(f):
    """Decorator para rotas que exigem login de cliente"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'client_id' not in session:
            if request.is_json:
                return jsonify({"error": "Autenticação necessária"}), 401
            flash("Faça login para continuar", "warning")
            return redirect(url_for('login_page'))
        
        # Verifica se cliente ainda existe e está ativo
        cliente = Cliente.query.get(session['client_id'])
        if not cliente or not cliente.ativo:
            session.pop('client_id', None)
            if request.is_json:
                return jsonify({"error": "Sessão inválida"}), 401
            return redirect(url_for('login_page'))
        
        g.cliente = cliente
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator para rotas que exigem login de admin"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged') or not session.get('admin_id'):
            if request.is_json:
                return jsonify({"error": "Acesso não autorizado"}), 401
            flash("Acesso restrito a administradores", "danger")
            return redirect(url_for('admin_login_page'))
        
        admin = Admin.query.get(session['admin_id'])
        if not admin or not admin.ativo:
            session.pop('admin_logged', None)
            session.pop('admin_id', None)
            if request.is_json:
                return jsonify({"error": "Sessão inválida"}), 401
            return redirect(url_for('admin_login_page'))
        
        g.admin = admin
        return f(*args, **kwargs)
    return decorated_function


def rate_limit(max_requests=10, window=60):
    """Decorator simples para rate limiting"""
    def decorator(f):
        requests_log = {}
        
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ip = request.remote_addr
            now = datetime.utcnow()
            
            # Limpa entradas antigas
            cutoff = now - timedelta(seconds=window)
            requests_log[ip] = [t for t in requests_log.get(ip, []) if t > cutoff]
            
            # Verifica limite
            if len(requests_log.get(ip, [])) >= max_requests:
                return jsonify({
                    "error": "Muitas requisições. Tente novamente em alguns minutos."
                }), 429
            
            # Registra requisição
            if ip not in requests_log:
                requests_log[ip] = []
            requests_log[ip].append(now)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(400)
def bad_request(e):
    if request.is_json:
        return jsonify({"error": "Requisição inválida"}), 400
    return render_template('errors/400.html'), 400


@app.errorhandler(401)
def unauthorized(e):
    if request.is_json:
        return jsonify({"error": "Não autorizado"}), 401
    return redirect(url_for('login_page'))


@app.errorhandler(403)
def forbidden(e):
    if request.is_json:
        return jsonify({"error": "Acesso proibido"}), 403
    return render_template('errors/403.html'), 403


@app.errorhandler(404)
def not_found(e):
    if request.is_json:
        return jsonify({"error": "Recurso não encontrado"}), 404
    return render_template('errors/404.html'), 404


@app.errorhandler(500)
def internal_error(e):
    db.session.rollback()
    logger.error(f"Erro interno: {e}")
    if request.is_json:
        return jsonify({"error": "Erro interno do servidor"}), 500
    return render_template('errors/500.html'), 500


# ============================================================
# CONTEXT PROCESSORS
# ============================================================

@app.context_processor
def inject_globals():
    """Injeta variáveis globais nos templates"""
    return {
        'now': datetime.utcnow(),
        'servicos': SERVICOS_DISPONIVEIS,
        'barbeiros': BARBEIROS,
    }


@app.before_request
def before_request():
    """Executado antes de cada requisição"""
    session.permanent = True
    g.request_start = datetime.utcnow()


@app.after_request
def after_request(response):
    """Executado após cada requisição"""
    # Headers de segurança
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Log de tempo de resposta
    if hasattr(g, 'request_start'):
        elapsed = (datetime.utcnow() - g.request_start).total_seconds()
        if elapsed > 1:  # Log requisições lentas
            logger.warning(f"Requisição lenta: {request.path} - {elapsed:.2f}s")
    
    return response


# ============================================================
# ROTAS - PÁGINAS PÚBLICAS
# ============================================================

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/cadastro")
def cadastro_page():
    if session.get('client_id'):
        return redirect(url_for('agendamento_page'))
    return render_template("cadastro.html")


@app.route("/login")
def login_page():
    if session.get('client_id'):
        return redirect(url_for('agendamento_page'))
    return render_template("login.html")


@app.route("/agendamento")
@login_required
def agendamento_page():
    return render_template("agendamento.html", cliente=g.cliente)


@app.route("/meus-agendamentos")
@login_required
def meus_agendamentos_page():
    return render_template("meus_agendamentos.html", cliente=g.cliente)


@app.route("/perfil")
@login_required
def perfil_page():
    return render_template("perfil.html", cliente=g.cliente)


@app.route("/sucesso")
def sucesso():
    return render_template("sucesso.html")


# ============================================================
# ROTAS - ADMIN
# ============================================================

@app.route("/admin-login", methods=["GET", "POST"])
def admin_login_page():
    if session.get('admin_logged'):
        return redirect(url_for('admin_painel'))
    
    if request.method == "POST":
        username = request.form.get("usuario", "").strip()
        password = request.form.get("senha", "")
        
        if not username or not password:
            return render_template("admin_login.html", erro="Preencha todos os campos")
        
        admin = Admin.query.filter_by(username=username).first()
        
        if admin and admin.ativo and admin.check_password(password):
            session["admin_logged"] = True
            session["admin_id"] = admin.id
            admin.ultimo_login = datetime.utcnow()
            db.session.commit()
            
            log_audit("admin_login", "admin", admin.id)
            logger.info(f"Admin login: {username}")
            
            return redirect(url_for("admin_painel"))
        
        logger.warning(f"Tentativa de login admin falha: {username}")
        return render_template("admin_login.html", erro="Usuário ou senha incorretos")
    
    return render_template("admin_login.html")


@app.route("/admin")
@admin_required
def admin_painel():
    # Estatísticas para o dashboard
    stats = {
        "total_clientes": Cliente.query.filter_by(ativo=True).count(),
        "total_agendamentos": Agendamento.query.count(),
        "agendamentos_hoje": Agendamento.query.filter(
            Agendamento.data == datetime.utcnow().date()
        ).count(),
        "agendamentos_pendentes": Agendamento.query.filter_by(
            status=StatusAgendamento.PENDENTE
        ).count(),
    }
    return render_template("admin.html", stats=stats)


@app.route("/admin-logout")
def admin_logout_page():
    if session.get('admin_id'):
        log_audit("admin_logout", "admin", session.get('admin_id'))
    
    session.pop("admin_logged", None)
    session.pop("admin_id", None)
    flash("Você saiu do painel com sucesso!", "info")
    return redirect(url_for("admin_login_page"))


# ============================================================
# API - AUTENTICAÇÃO
# ============================================================

@app.route("/api/register", methods=["POST"])
@rate_limit(max_requests=5, window=60)
def api_register():
    """Cadastro de novo cliente"""
    data = request.json or {}
    errors = {}
    
    # Validações
    nome = (data.get("nome") or "").strip()
    if not nome or len(nome) < 3:
        errors["nome"] = "Nome deve ter pelo menos 3 caracteres"
    
    cpf = only_digits(data.get("cpf") or "")
    if not cpf:
        errors["cpf"] = "CPF é obrigatório"
    elif not valida_cpf(cpf):
        errors["cpf"] = "CPF inválido"
    elif Cliente.query.filter_by(cpf=cpf).first():
        errors["cpf"] = "CPF já cadastrado"
    
    password = (data.get("password") or "")
    if not password or len(password) < 6:
        errors["password"] = "Senha deve ter pelo menos 6 caracteres"
    
    password2 = data.get("password2") or data.get("confirmPassword") or ""
    if password != password2:
        errors["password2"] = "Senhas não conferem"
    
    email = (data.get("email") or "").lower().strip()
    if email:
        if not valida_email(email):
            errors["email"] = "E-mail inválido"
        elif Cliente.query.filter_by(email=email).first():
            errors["email"] = "E-mail já cadastrado"
    
    telefone = only_digits(data.get("telefone") or "")
    if telefone and not valida_telefone(telefone):
        errors["telefone"] = "Telefone inválido"
    
    cep = only_digits(data.get("cep") or "")
    if cep and not valida_cep(cep):
        errors["cep"] = "CEP inválido"
    
    # Retorna erros se houver
    if errors:
        return jsonify({"error": "Dados inválidos", "errors": errors}), 400
    
    try:
        # Cria cliente
        cliente = Cliente(
            nome=nome,
            cpf=cpf,
            email=email or None,
            telefone=telefone or None,
            cep=cep or None,
            endereco=(data.get("endereco") or "").strip() or None,
            numero=(data.get("numero") or "").strip() or None,
            complemento=(data.get("complemento") or "").strip() or None,
            observacoes=(data.get("observacoes") or "").strip() or None,
        )
        cliente.set_password(password)
        
        db.session.add(cliente)
        db.session.commit()
        
        # Faz login automático
        session['client_id'] = cliente.id
        
        log_audit("cliente_cadastro", "cliente", cliente.id)
        logger.info(f"Novo cliente cadastrado: {cliente.nome} (ID: {cliente.id})")
        
        return jsonify({
            "ok": True,
            "id": cliente.id,
            "message": "Cadastro realizado com sucesso!"
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao cadastrar cliente: {e}")
        return jsonify({"error": "Erro ao processar cadastro"}), 500


@app.route("/api/login", methods=["POST"])
@rate_limit(max_requests=10, window=60)
def api_login():
    """Login de cliente"""
    data = request.json or {}
    
    cpf = only_digits(data.get("cpf") or "")
    password = (data.get("password") or "")
    
    if not cpf or not password:
        return jsonify({"error": "CPF e senha são obrigatórios"}), 400
    
    cliente = Cliente.query.filter_by(cpf=cpf).first()
    
    if not cliente:
        return jsonify({"error": "CPF ou senha incorretos"}), 401
    
    # Verifica se está bloqueado
    if cliente.esta_bloqueado():
        minutos_restantes = int((cliente.bloqueado_ate - datetime.utcnow()).total_seconds() / 60) + 1
        return jsonify({
            "error": f"Conta bloqueada. Tente novamente em {minutos_restantes} minutos."
        }), 429
    
    # Verifica se está ativo
    if not cliente.ativo:
        return jsonify({"error": "Conta desativada. Entre em contato com o suporte."}), 403
    
    # Verifica senha
    if not cliente.check_password(password):
        cliente.registrar_tentativa_falha()
        tentativas_restantes = 5 - cliente.tentativas_login
        
        if tentativas_restantes > 0:
            return jsonify({
                "error": f"CPF ou senha incorretos. {tentativas_restantes} tentativas restantes."
            }), 401
        else:
            return jsonify({
                "error": "Conta bloqueada por 15 minutos devido a muitas tentativas."
            }), 429
    
    # Login bem-sucedido
    cliente.resetar_tentativas()
    session['client_id'] = cliente.id
    
    log_audit("cliente_login", "cliente", cliente.id)
    logger.info(f"Cliente login: {cliente.nome} (ID: {cliente.id})")
    
    return jsonify({
        "ok": True,
        "id": cliente.id,
        "nome": cliente.nome,
        "message": f"Bem-vindo(a), {cliente.nome.split()[0]}!"
    })


@app.route("/api/logout", methods=["POST"])
def api_logout():
    """Logout de cliente"""
    client_id = session.get('client_id')
    if client_id:
        log_audit("cliente_logout", "cliente", client_id)
    
    session.pop('client_id', None)
    return jsonify({"ok": True, "message": "Logout realizado com sucesso"})


@app.route("/api/me")
def api_me():
    """Retorna dados do cliente logado"""
    client_id = session.get('client_id')
    if not client_id:
        return jsonify(None)
    
    cliente = Cliente.query.get(client_id)
    if not cliente or not cliente.ativo:
        session.pop('client_id', None)
        return jsonify(None)
    
    return jsonify(cliente.to_dict(include_sensitive=True))


@app.route("/api/me", methods=["PUT"])
@login_required
def api_update_me():
    """Atualiza dados do cliente logado"""
    data = request.json or {}
    cliente = g.cliente
    errors = {}
    
    # Campos atualizáveis
    if "nome" in data:
        nome = data["nome"].strip()
        if len(nome) < 3:
            errors["nome"] = "Nome deve ter pelo menos 3 caracteres"
        else:
            cliente.nome = nome
    
    if "email" in data:
        email = (data["email"] or "").lower().strip()
        if email:
            if not valida_email(email):
                errors["email"] = "E-mail inválido"
            elif email != cliente.email:
                if Cliente.query.filter(Cliente.email == email, Cliente.id != cliente.id).first():
                    errors["email"] = "E-mail já cadastrado"
                else:
                    cliente.email = email
                    cliente.email_verificado = False
        else:
            cliente.email = None
    
    if "telefone" in data:
        telefone = only_digits(data["telefone"] or "")
        if telefone and not valida_telefone(telefone):
            errors["telefone"] = "Telefone inválido"
        else:
            cliente.telefone = telefone or None
    
    if "cep" in data:
        cep = only_digits(data["cep"] or "")
        if cep and not valida_cep(cep):
            errors["cep"] = "CEP inválido"
        else:
            cliente.cep = cep or None
    
    if "endereco" in data:
        cliente.endereco = (data["endereco"] or "").strip() or None
    
    if "numero" in data:
        cliente.numero = (data["numero"] or "").strip() or None
    
    if "complemento" in data:
        cliente.complemento = (data["complemento"] or "").strip() or None
    
    if "observacoes" in data:
        cliente.observacoes = (data["observacoes"] or "").strip() or None
    
    if errors:
        return jsonify({"error": "Dados inválidos", "errors": errors}), 400
    
    try:
        db.session.commit()
        log_audit("cliente_update", "cliente", cliente.id)
        return jsonify({
            "ok": True,
            "message": "Dados atualizados com sucesso",
            "cliente": cliente.to_dict(include_sensitive=True)
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao atualizar cliente: {e}")
        return jsonify({"error": "Erro ao atualizar dados"}), 500


@app.route("/api/me/password", methods=["PUT"])
@login_required
def api_change_password():
    """Altera senha do cliente"""
    data = request.json or {}
    cliente = g.cliente
    
    senha_atual = data.get("senha_atual") or ""
    nova_senha = data.get("nova_senha") or ""
    confirmar_senha = data.get("confirmar_senha") or ""
    
    if not senha_atual:
        return jsonify({"error": "Senha atual é obrigatória"}), 400
    
    if not cliente.check_password(senha_atual):
        return jsonify({"error": "Senha atual incorreta"}), 401
    
    if len(nova_senha) < 6:
        return jsonify({"error": "Nova senha deve ter pelo menos 6 caracteres"}), 400
    
    if nova_senha != confirmar_senha:
        return jsonify({"error": "Senhas não conferem"}), 400
    
    if senha_atual == nova_senha:
        return jsonify({"error": "Nova senha deve ser diferente da atual"}), 400
    
    try:
        cliente.set_password(nova_senha)
        db.session.commit()
        log_audit("cliente_password_change", "cliente", cliente.id)
        return jsonify({"ok": True, "message": "Senha alterada com sucesso"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao alterar senha: {e}")
        return jsonify({"error": "Erro ao alterar senha"}), 500


# ============================================================
# API - AGENDAMENTOS (CLIENTE)
# ============================================================

@app.route("/api/servicos")
def api_servicos():
    """Lista serviços disponíveis"""
    return jsonify(SERVICOS_DISPONIVEIS)


@app.route("/api/barbeiros")
def api_barbeiros():
    """Lista barbeiros disponíveis"""
    return jsonify(BARBEIROS)


@app.route("/api/horarios-disponiveis")
def api_horarios_disponiveis():
    """Retorna horários disponíveis para uma data e barbeiro"""
    data_str = request.args.get("data")
    barbeiro = request.args.get("barbeiro")
    servico = request.args.get("servico")
    
    if not data_str or not barbeiro:
        return jsonify({"error": "Data e barbeiro são obrigatórios"}), 400
    
    try:
        data = datetime.strptime(data_str, "%Y-%m-%d").date()
    except ValueError:
        return jsonify({"error": "Data inválida"}), 400
    
    # Verifica se é dia de funcionamento
    if data.weekday() not in HORARIOS_FUNCIONAMENTO["dias_semana"]:
        return jsonify({"horarios": [], "message": "Não funcionamos neste dia"})
    
    # Verifica se é data passada
    if data < datetime.utcnow().date():
        return jsonify({"horarios": [], "message": "Data não disponível"})
    
    # Busca duração do serviço
    duracao = 30  # padrão
    if servico:
        servico_info = next((s for s in SERVICOS_DISPONIVEIS if s["id"] == servico), None)
        if servico_info:
            duracao = servico_info["duracao"]
    
    # Gera todos os horários possíveis
    inicio = datetime.strptime(HORARIOS_FUNCIONAMENTO["inicio"], "%H:%M")
    fim = datetime.strptime(HORARIOS_FUNCIONAMENTO["fim"], "%H:%M")
    intervalo = timedelta(minutes=HORARIOS_FUNCIONAMENTO["intervalo"])
    
    todos_horarios = []
    atual = inicio
    while atual.time() < fim.time():
        todos_horarios.append(atual.strftime("%H:%M"))
        atual += intervalo
    
    # Busca agendamentos existentes
    agendamentos = Agendamento.query.filter(
        Agendamento.data == data,
        Agendamento.barbeiro == barbeiro,
        Agendamento.status.in_([StatusAgendamento.PENDENTE, StatusAgendamento.CONFIRMADO])
    ).all()
    
    horarios_ocupados = set()
    for ag in agendamentos:
        horarios_ocupados.add(ag.horario.strftime("%H:%M"))
        # Bloqueia horários adjacentes baseado na duração
        if ag.duracao_minutos:
            slots_ocupados = ag.duracao_minutos // HORARIOS_FUNCIONAMENTO["intervalo"]
            hora_ag = datetime.combine(data, ag.horario)
            for i in range(1, slots_ocupados):
                hora_bloqueada = hora_ag + timedelta(minutes=i * HORARIOS_FUNCIONAMENTO["intervalo"])
                horarios_ocupados.add(hora_bloqueada.strftime("%H:%M"))
    
    # Se for hoje, remove horários passados
    if data == datetime.utcnow().date():
        agora = datetime.utcnow().time()
        todos_horarios = [h for h in todos_horarios if datetime.strptime(h, "%H:%M").time() > agora]
    
    # Filtra disponíveis
    horarios_disponiveis = [h for h in todos_horarios if h not in horarios_ocupados]
    
    return jsonify({
        "data": data_str,
        "barbeiro": barbeiro,
        "horarios": horarios_disponiveis
    })


@app.route("/api/agendar", methods=["POST"])
@login_required
def api_agendar():
    """Cria novo agendamento"""
    data = request.json or {}
    cliente = g.cliente
    errors = {}
    
    # Validações
    servico = (data.get("servico") or "").strip()
    if not servico:
        errors["servico"] = "Selecione um serviço"
    elif not any(s["id"] == servico for s in SERVICOS_DISPONIVEIS):
        errors["servico"] = "Serviço inválido"
    
    barbeiro = (data.get("barbeiro") or "").strip()
    if not barbeiro:
        errors["barbeiro"] = "Selecione um barbeiro"
    elif not any(b["id"] == barbeiro for b in BARBEIROS):
        errors["barbeiro"] = "Barbeiro inválido"
    
    data_str = (data.get("data") or "").strip()
    if not data_str:
        errors["data"] = "Selecione uma data"
    else:
        try:
            data_ag = datetime.strptime(data_str, "%Y-%m-%d").date()
            if data_ag < datetime.utcnow().date():
                errors["data"] = "Data não pode ser no passado"
            elif data_ag.weekday() not in HORARIOS_FUNCIONAMENTO["dias_semana"]:
                errors["data"] = "Não funcionamos neste dia"
        except ValueError:
            errors["data"] = "Data inválida"
    
    horario_str = (data.get("horario") or "").strip()
    if not horario_str:
        errors["horario"] = "Selecione um horário"
    else:
        try:
            horario = datetime.strptime(horario_str, "%H:%M").time()
        except ValueError:
            errors["horario"] = "Horário inválido"
    
    if errors:
        return jsonify({"error": "Dados inválidos", "errors": errors}), 400
    
    # Verifica disponibilidade
    existe = Agendamento.query.filter(
        Agendamento.data == data_ag,
        Agendamento.horario == horario,
        Agendamento.barbeiro == barbeiro,
        Agendamento.status.in_([StatusAgendamento.PENDENTE, StatusAgendamento.CONFIRMADO])
    ).first()
    
    if existe:
        return jsonify({"error": "Horário não disponível. Por favor, escolha outro."}), 409
    
    # Busca info do serviço
    servico_info = next((s for s in SERVICOS_DISPONIVEIS if s["id"] == servico), {})
    
    try:
        agendamento = Agendamento(
            cliente_id=cliente.id,
            servico=servico,
            barbeiro=barbeiro,
            data=data_ag,
            horario=horario,
            preco=servico_info.get("preco"),
            duracao_minutos=servico_info.get("duracao"),
            observacoes=(data.get("observacoes") or "").strip() or None,
            status=StatusAgendamento.PENDENTE
        )
        
        db.session.add(agendamento)
        db.session.commit()
        
        log_audit("agendamento_criar", "agendamento", agendamento.id)
        logger.info(f"Novo agendamento: cliente_id={cliente.id} {data_ag} {horario_str}")
        
        return jsonify({
            "ok": True,
            "id": agendamento.id,
            "message": "Agendamento realizado com sucesso!",
            "agendamento": agendamento.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao criar agendamento: {e}")
        return jsonify({"error": "Erro ao processar agendamento"}), 500


@app.route("/api/meus-agendamentos")
@login_required
def api_meus_agendamentos():
    """Lista agendamentos do cliente logado"""
    cliente = g.cliente
    
    # Parâmetros de filtro
    status = request.args.get("status")
    periodo = request.args.get("periodo", "todos")  # futuros, passados, todos
    
    query = Agendamento.query.filter_by(cliente_id=cliente.id)
    
    if status:
        query = query.filter_by(status=status)
    
    hoje = datetime.utcnow().date()
    if periodo == "futuros":
        query = query.filter(Agendamento.data >= hoje)
    elif periodo == "passados":
        query = query.filter(Agendamento.data < hoje)
    
    agendamentos = query.order_by(Agendamento.data.desc(), Agendamento.horario.desc()).all()
    
    return jsonify({
        "total": len(agendamentos),
        "agendamentos": [ag.to_dict() for ag in agendamentos]
    })


@app.route("/api/agendamento/<int:id>")
@login_required
def api_get_agendamento(id):
    """Retorna detalhes de um agendamento"""
    cliente = g.cliente
    
    agendamento = Agendamento.query.filter_by(id=id, cliente_id=cliente.id).first()
    
    if not agendamento:
        return jsonify({"error": "Agendamento não encontrado"}), 404
    
    return jsonify(agendamento.to_dict())


@app.route("/api/agendamento/<int:id>/cancelar", methods=["POST"])
@login_required
def api_cancelar_agendamento(id):
    """Cancela um agendamento"""
    cliente = g.cliente
    data = request.json or {}
    
    agendamento = Agendamento.query.filter_by(id=id, cliente_id=cliente.id).first()
    
    if not agendamento:
        return jsonify({"error": "Agendamento não encontrado"}), 404
    
    if agendamento.status == StatusAgendamento.CANCELADO:
        return jsonify({"error": "Agendamento já está cancelado"}), 400
    
    if agendamento.status == StatusAgendamento.CONCLUIDO:
        return jsonify({"error": "Não é possível cancelar agendamento concluído"}), 400
    
    if not agendamento.pode_cancelar:
        return jsonify({
            "error": "Cancelamento permitido apenas até 2 horas antes do horário"
        }), 400
    
    try:
        agendamento.status = StatusAgendamento.CANCELADO
        agendamento.cancelado_em = datetime.utcnow()
        agendamento.motivo_cancelamento = (data.get("motivo") or "").strip()[:200] or None
        
        db.session.commit()
        
        log_audit("agendamento_cancelar", "agendamento", agendamento.id)
        logger.info(f"Agendamento cancelado: id={id} cliente_id={cliente.id}")
        
        return jsonify({
            "ok": True,
            "message": "Agendamento cancelado com sucesso"
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao cancelar agendamento: {e}")
        return jsonify({"error": "Erro ao cancelar agendamento"}), 500


# ============================================================
# API - ADMIN
# ============================================================

@app.route("/api/admin/stats")
@admin_required
def admin_stats():
    """Estatísticas do dashboard admin"""
    hoje = datetime.utcnow().date()
    inicio_mes = hoje.replace(day=1)
    inicio_semana = hoje - timedelta(days=hoje.weekday())
    
    # Estatísticas gerais
    stats = {
        "clientes": {
            "total": Cliente.query.filter_by(ativo=True).count(),
            "novos_mes": Cliente.query.filter(
                Cliente.criado_em >= inicio_mes,
                Cliente.ativo == True
            ).count(),
            "novos_semana": Cliente.query.filter(
                Cliente.criado_em >= inicio_semana,
                Cliente.ativo == True
            ).count(),
        },
        "agendamentos": {
            "total": Agendamento.query.count(),
            "hoje": Agendamento.query.filter(Agendamento.data == hoje).count(),
            "semana": Agendamento.query.filter(Agendamento.data >= inicio_semana).count(),
            "pendentes": Agendamento.query.filter_by(status=StatusAgendamento.PENDENTE).count(),
            "confirmados": Agendamento.query.filter_by(status=StatusAgendamento.CONFIRMADO).count(),
            "concluidos_mes": Agendamento.query.filter(
                Agendamento.data >= inicio_mes,
                Agendamento.status == StatusAgendamento.CONCLUIDO
            ).count(),
            "cancelados_mes": Agendamento.query.filter(
                Agendamento.data >= inicio_mes,
                Agendamento.status == StatusAgendamento.CANCELADO
            ).count(),
        },
        "faturamento": {
            "hoje": float(db.session.query(db.func.sum(Agendamento.preco)).filter(
                Agendamento.data == hoje,
                Agendamento.status == StatusAgendamento.CONCLUIDO
            ).scalar() or 0),
            "semana": float(db.session.query(db.func.sum(Agendamento.preco)).filter(
                Agendamento.data >= inicio_semana,
                Agendamento.status == StatusAgendamento.CONCLUIDO
            ).scalar() or 0),
            "mes": float(db.session.query(db.func.sum(Agendamento.preco)).filter(
                Agendamento.data >= inicio_mes,
                Agendamento.status == StatusAgendamento.CONCLUIDO
            ).scalar() or 0),
        }
    }
    
    # Agendamentos por barbeiro (mês atual)
    stats["por_barbeiro"] = []
    for barbeiro in BARBEIROS:
        count = Agendamento.query.filter(
            Agendamento.barbeiro == barbeiro["id"],
            Agendamento.data >= inicio_mes
        ).count()
        stats["por_barbeiro"].append({
            "id": barbeiro["id"],
            "nome": barbeiro["nome"],
            "agendamentos": count
        })
    
    # Serviços mais populares (mês atual)
    stats["servicos_populares"] = []
    for servico in SERVICOS_DISPONIVEIS:
        count = Agendamento.query.filter(
            Agendamento.servico == servico["id"],
            Agendamento.data >= inicio_mes
        ).count()
        stats["servicos_populares"].append({
            "id": servico["id"],
            "nome": servico["nome"],
            "agendamentos": count
        })
    stats["servicos_populares"].sort(key=lambda x: x["agendamentos"], reverse=True)
    
    return jsonify(stats)


@app.route("/api/admin/clients")
@admin_required
def admin_clients():
    """Lista todos os clientes"""
    # Parâmetros de paginação e filtro
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    search = request.args.get("search", "").strip()
    status = request.args.get("status")  # ativo, inativo
    order_by = request.args.get("order_by", "criado_em")
    order_dir = request.args.get("order_dir", "desc")
    
    query = Cliente.query
    
    # Filtro de busca
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            db.or_(
                Cliente.nome.ilike(search_term),
                Cliente.cpf.ilike(search_term),
                Cliente.email.ilike(search_term),
                Cliente.telefone.ilike(search_term)
            )
        )
    
    # Filtro de status
    if status == "ativo":
        query = query.filter_by(ativo=True)
    elif status == "inativo":
        query = query.filter_by(ativo=False)
    
    # Ordenação
    order_column = getattr(Cliente, order_by, Cliente.criado_em)
    if order_dir == "desc":
        order_column = order_column.desc()
    query = query.order_by(order_column)
    
    # Paginação
    per_page = min(per_page, 100)  # Máximo 100 por página
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        "total": pagination.total,
        "pages": pagination.pages,
        "page": page,
        "per_page": per_page,
        "clientes": [c.to_dict(include_sensitive=True) for c in pagination.items]
    })


@app.route("/api/admin/client/<int:id>")
@admin_required
def admin_get_client(id):
    """Retorna detalhes de um cliente"""
    cliente = Cliente.query.get_or_404(id)
    
    # Inclui agendamentos recentes
    agendamentos = Agendamento.query.filter_by(cliente_id=id)\
        .order_by(Agendamento.data.desc())\
        .limit(10)\
        .all()
    
    data = cliente.to_dict(include_sensitive=True)
    data["agendamentos_recentes"] = [ag.to_dict() for ag in agendamentos]
    data["total_agendamentos"] = Agendamento.query.filter_by(cliente_id=id).count()
    
    return jsonify(data)


@app.route("/api/admin/client/<int:id>", methods=["PUT"])
@admin_required
def admin_update_client(id):
    """Atualiza dados de um cliente"""
    cliente = Cliente.query.get_or_404(id)
    data = request.json or {}
    
    # Campos atualizáveis pelo admin
    if "nome" in data:
        cliente.nome = data["nome"].strip()
    
    if "email" in data:
        email = (data["email"] or "").lower().strip()
        if email and email != cliente.email:
            if Cliente.query.filter(Cliente.email == email, Cliente.id != id).first():
                return jsonify({"error": "E-mail já cadastrado"}), 400
        cliente.email = email or None
    
    if "telefone" in data:
        cliente.telefone = only_digits(data["telefone"]) or None
    
    if "endereco" in data:
        cliente.endereco = (data["endereco"] or "").strip() or None
    
    if "cep" in data:
        cliente.cep = only_digits(data["cep"]) or None
    
    if "numero" in data:
        cliente.numero = (data["numero"] or "").strip() or None
    
    if "complemento" in data:
        cliente.complemento = (data["complemento"] or "").strip() or None
    
    if "observacoes" in data:
        cliente.observacoes = (data["observacoes"] or "").strip() or None
    
    if "ativo" in data:
        cliente.ativo = bool(data["ativo"])
    
    try:
        db.session.commit()
        log_audit("admin_update_client", "cliente", id, f"Admin: {g.admin.username}")
        return jsonify({"ok": True, "message": "Cliente atualizado", "cliente": cliente.to_dict(include_sensitive=True)})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao atualizar cliente: {e}")
        return jsonify({"error": "Erro ao atualizar cliente"}), 500


@app.route("/api/admin/client/<int:id>", methods=["DELETE"])
@admin_required
def admin_delete_client(id):
    """Desativa ou exclui um cliente"""
    cliente = Cliente.query.get_or_404(id)
    
    # Soft delete por padrão
    hard_delete = request.args.get("hard", "false").lower() == "true"
    
    try:
        if hard_delete:
            # Exclui permanentemente
            db.session.delete(cliente)
            log_audit("admin_delete_client_hard", "cliente", id, f"Admin: {g.admin.username}")
            message = "Cliente excluído permanentemente"
        else:
            # Soft delete
            cliente.ativo = False
            log_audit("admin_delete_client_soft", "cliente", id, f"Admin: {g.admin.username}")
            message = "Cliente desativado"
        
        db.session.commit()
        return jsonify({"ok": True, "message": message})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao excluir cliente: {e}")
        return jsonify({"error": "Erro ao excluir cliente"}), 500


@app.route("/api/admin/client/<int:id>/reset-password", methods=["POST"])
@admin_required
def admin_reset_client_password(id):
    """Reseta senha do cliente"""
    cliente = Cliente.query.get_or_404(id)
    data = request.json or {}
    
    nova_senha = data.get("nova_senha") or ""
    
    if len(nova_senha) < 6:
        return jsonify({"error": "Senha deve ter pelo menos 6 caracteres"}), 400
    
    try:
        cliente.set_password(nova_senha)
        cliente.tentativas_login = 0
        cliente.bloqueado_ate = None
        db.session.commit()
        
        log_audit("admin_reset_password", "cliente", id, f"Admin: {g.admin.username}")
        return jsonify({"ok": True, "message": "Senha resetada com sucesso"})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao resetar senha: {e}")
        return jsonify({"error": "Erro ao resetar senha"}), 500


@app.route("/api/admin/agendamentos")
@admin_required
def admin_agendamentos():
    """Lista todos os agendamentos"""
    # Parâmetros
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    status = request.args.get("status")
    barbeiro = request.args.get("barbeiro")
    data_inicio = request.args.get("data_inicio")
    data_fim = request.args.get("data_fim")
    cliente_id = request.args.get("cliente_id", type=int)
    
    query = Agendamento.query
    
    # Filtros
    if status:
        query = query.filter_by(status=status)
    
    if barbeiro:
        query = query.filter_by(barbeiro=barbeiro)
    
    if cliente_id:
        query = query.filter_by(cliente_id=cliente_id)
    
    if data_inicio:
        try:
            data_ini = datetime.strptime(data_inicio, "%Y-%m-%d").date()
            query = query.filter(Agendamento.data >= data_ini)
        except ValueError:
            pass
    
    if data_fim:
        try:
            data_f = datetime.strptime(data_fim, "%Y-%m-%d").date()
            query = query.filter(Agendamento.data <= data_f)
        except ValueError:
            pass
    
    # Ordenação
    query = query.order_by(Agendamento.data.desc(), Agendamento.horario.desc())
    
    # Paginação
    per_page = min(per_page, 100)
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        "total": pagination.total,
        "pages": pagination.pages,
        "page": page,
        "per_page": per_page,
        "agendamentos": [ag.to_dict() for ag in pagination.items]
    })


@app.route("/api/admin/agendamentos/hoje")
@admin_required
def admin_agendamentos_hoje():
    """Lista agendamentos de hoje"""
    hoje = datetime.utcnow().date()
    
    agendamentos = Agendamento.query.filter(
        Agendamento.data == hoje,
        Agendamento.status.in_([StatusAgendamento.PENDENTE, StatusAgendamento.CONFIRMADO])
    ).order_by(Agendamento.horario).all()
    
    # Agrupa por barbeiro
    por_barbeiro = {}
    for barbeiro in BARBEIROS:
        por_barbeiro[barbeiro["id"]] = {
            "barbeiro": barbeiro,
            "agendamentos": []
        }
    
    for ag in agendamentos:
        if ag.barbeiro in por_barbeiro:
            por_barbeiro[ag.barbeiro]["agendamentos"].append(ag.to_dict())
    
    return jsonify({
        "data": hoje.isoformat(),
        "total": len(agendamentos),
        "por_barbeiro": list(por_barbeiro.values())
    })


@app.route("/api/admin/agendamento/<int:id>")
@admin_required
def admin_get_agendamento(id):
    """Retorna detalhes de um agendamento"""
    agendamento = Agendamento.query.get_or_404(id)
    
    data = agendamento.to_dict()
    data["cliente"] = agendamento.cliente.to_dict() if agendamento.cliente else None
    
    return jsonify(data)


@app.route("/api/admin/agendamento/<int:id>", methods=["PUT"])
@admin_required
def admin_update_agendamento(id):
    """Atualiza um agendamento"""
    agendamento = Agendamento.query.get_or_404(id)
    data = request.json or {}
    
    # Campos atualizáveis
    if "status" in data:
        if data["status"] in [StatusAgendamento.PENDENTE, StatusAgendamento.CONFIRMADO, 
                              StatusAgendamento.CONCLUIDO, StatusAgendamento.CANCELADO]:
            agendamento.status = data["status"]
            if data["status"] == StatusAgendamento.CANCELADO:
                agendamento.cancelado_em = datetime.utcnow()
    
    if "servico" in data:
        servico = data["servico"]
        if any(s["id"] == servico for s in SERVICOS_DISPONIVEIS):
            agendamento.servico = servico
            servico_info = next((s for s in SERVICOS_DISPONIVEIS if s["id"] == servico), {})
            agendamento.preco = servico_info.get("preco")
            agendamento.duracao_minutos = servico_info.get("duracao")
    
    if "barbeiro" in data:
        barbeiro = data["barbeiro"]
        if any(b["id"] == barbeiro for b in BARBEIROS):
            agendamento.barbeiro = barbeiro
    
    if "data" in data:
        try:
            agendamento.data = datetime.strptime(data["data"], "%Y-%m-%d").date()
        except ValueError:
            return jsonify({"error": "Data inválida"}), 400
    
    if "horario" in data:
        try:
            agendamento.horario = datetime.strptime(data["horario"], "%H:%M").time()
        except ValueError:
            return jsonify({"error": "Horário inválido"}), 400
    
    if "observacoes" in data:
        agendamento.observacoes = (data["observacoes"] or "").strip() or None
    
    if "motivo_cancelamento" in data:
        agendamento.motivo_cancelamento = (data["motivo_cancelamento"] or "").strip()[:200] or None
    
    try:
        db.session.commit()
        log_audit("admin_update_agendamento", "agendamento", id, f"Admin: {g.admin.username}")
        return jsonify({
            "ok": True,
            "message": "Agendamento atualizado",
            "agendamento": agendamento.to_dict()
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao atualizar agendamento: {e}")
        return jsonify({"error": "Erro ao atualizar agendamento"}), 500


@app.route("/api/admin/agendamento/<int:id>", methods=["DELETE"])
@admin_required
def admin_delete_agendamento(id):
    """Exclui um agendamento"""
    agendamento = Agendamento.query.get_or_404(id)
    
    try:
        db.session.delete(agendamento)
        db.session.commit()
        log_audit("admin_delete_agendamento", "agendamento", id, f"Admin: {g.admin.username}")
        return jsonify({"ok": True, "message": "Agendamento excluído"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao excluir agendamento: {e}")
        return jsonify({"error": "Erro ao excluir agendamento"}), 500


@app.route("/api/admin/agendamento/<int:id>/confirmar", methods=["POST"])
@admin_required
def admin_confirmar_agendamento(id):
    """Confirma um agendamento"""
    agendamento = Agendamento.query.get_or_404(id)
    
    if agendamento.status != StatusAgendamento.PENDENTE:
        return jsonify({"error": "Apenas agendamentos pendentes podem ser confirmados"}), 400
    
    agendamento.status = StatusAgendamento.CONFIRMADO
    db.session.commit()
    
    log_audit("admin_confirmar_agendamento", "agendamento", id)
    return jsonify({"ok": True, "message": "Agendamento confirmado"})


@app.route("/api/admin/agendamento/<int:id>/concluir", methods=["POST"])
@admin_required
def admin_concluir_agendamento(id):
    """Marca agendamento como concluído"""
    agendamento = Agendamento.query.get_or_404(id)
    
    if agendamento.status == StatusAgendamento.CANCELADO:
        return jsonify({"error": "Agendamento cancelado não pode ser concluído"}), 400
    
    agendamento.status = StatusAgendamento.CONCLUIDO
    db.session.commit()
    
    log_audit("admin_concluir_agendamento", "agendamento", id)
    return jsonify({"ok": True, "message": "Agendamento concluído"})


# ============================================================
# API - EXPORTAÇÃO
# ============================================================

@app.route("/api/admin/export/clientes")
@admin_required
def admin_export_clientes_csv():
    """Exporta clientes para CSV"""
    clientes = Cliente.query.order_by(Cliente.id.desc()).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Cabeçalho
    writer.writerow([
        'ID', 'Nome', 'CPF', 'E-mail', 'Telefone', 'CEP', 
        'Endereço', 'Número', 'Complemento', 'Observações',
        'Ativo', 'Criado em', 'Último login'
    ])
    
    # Dados
    for c in clientes:
        writer.writerow([
            c.id,
            c.nome,
            c.cpf_formatado,
            c.email or '',
            c.telefone_formatado or '',
            formata_cep(c.cep) if c.cep else '',
            c.endereco or '',
            c.numero or '',
            c.complemento or '',
            c.observacoes or '',
            'Sim' if c.ativo else 'Não',
            c.criado_em.strftime('%d/%m/%Y %H:%M') if c.criado_em else '',
            c.ultimo_login.strftime('%d/%m/%Y %H:%M') if c.ultimo_login else ''
        ])
    
    mem = io.BytesIO()
    mem.write(output.getvalue().encode('utf-8-sig'))  # BOM para Excel
    mem.seek(0)
    
    log_audit("admin_export_clientes", details=f"Total: {len(clientes)}")
    
    return send_file(
        mem,
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'clientes_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv'
    )


@app.route("/api/admin/export/agendamentos")
@admin_required
def admin_export_agendamentos_csv():
    """Exporta agendamentos para CSV"""
    # Filtros opcionais
    data_inicio = request.args.get("data_inicio")
    data_fim = request.args.get("data_fim")
    
    query = Agendamento.query
    
    if data_inicio:
        try:
            data_ini = datetime.strptime(data_inicio, "%Y-%m-%d").date()
            query = query.filter(Agendamento.data >= data_ini)
        except ValueError:
            pass
    
    if data_fim:
        try:
            data_f = datetime.strptime(data_fim, "%Y-%m-%d").date()
            query = query.filter(Agendamento.data <= data_f)
        except ValueError:
            pass
    
    agendamentos = query.order_by(Agendamento.data.desc(), Agendamento.horario.desc()).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Cabeçalho
    writer.writerow([
        'ID', 'Cliente', 'CPF Cliente', 'Serviço', 'Barbeiro',
        'Data', 'Horário', 'Status', 'Preço', 'Duração (min)',
        'Observações', 'Criado em'
    ])
    
    # Dados
    for ag in agendamentos:
        servico_nome = ag.servico_info.get("nome") if ag.servico_info else ag.servico
        barbeiro_nome = ag.barbeiro_info.get("nome") if ag.barbeiro_info else ag.barbeiro
        
        writer.writerow([
            ag.id,
            ag.cliente.nome if ag.cliente else '',
            ag.cliente.cpf_formatado if ag.cliente else '',
            servico_nome,
            barbeiro_nome,
            ag.data.strftime('%d/%m/%Y') if ag.data else '',
            ag.horario.strftime('%H:%M') if ag.horario else '',
            ag.status,
            f'R$ {ag.preco:.2f}' if ag.preco else '',
            ag.duracao_minutos or '',
            ag.observacoes or '',
            ag.criado_em.strftime('%d/%m/%Y %H:%M') if ag.criado_em else ''
        ])
    
    mem = io.BytesIO()
    mem.write(output.getvalue().encode('utf-8-sig'))
    mem.seek(0)
    
    log_audit("admin_export_agendamentos", details=f"Total: {len(agendamentos)}")
    
    return send_file(
        mem,
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'agendamentos_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv'
    )


@app.route("/api/admin/export/relatorio")
@admin_required
def admin_export_relatorio():
    """Gera relatório completo em JSON"""
    hoje = datetime.utcnow().date()
    inicio_mes = hoje.replace(day=1)
    
    relatorio = {
        "gerado_em": datetime.utcnow().isoformat(),
        "periodo": {
            "inicio": inicio_mes.isoformat(),
            "fim": hoje.isoformat()
        },
        "resumo": {
            "total_clientes": Cliente.query.filter_by(ativo=True).count(),
            "novos_clientes_mes": Cliente.query.filter(
                Cliente.criado_em >= inicio_mes
            ).count(),
            "total_agendamentos_mes": Agendamento.query.filter(
                Agendamento.data >= inicio_mes
            ).count(),
            "agendamentos_concluidos": Agendamento.query.filter(
                Agendamento.data >= inicio_mes,
                Agendamento.status == StatusAgendamento.CONCLUIDO
            ).count(),
            "agendamentos_cancelados": Agendamento.query.filter(
                Agendamento.data >= inicio_mes,
                Agendamento.status == StatusAgendamento.CANCELADO
            ).count(),
            "faturamento_mes": float(db.session.query(
                db.func.sum(Agendamento.preco)
            ).filter(
                Agendamento.data >= inicio_mes,
                Agendamento.status == StatusAgendamento.CONCLUIDO
            ).scalar() or 0)
        },
        "por_barbeiro": [],
        "por_servico": [],
        "por_dia_semana": []
    }
    
    # Por barbeiro
    for barbeiro in BARBEIROS:
        dados = {
            "barbeiro": barbeiro["nome"],
            "agendamentos": Agendamento.query.filter(
                Agendamento.barbeiro == barbeiro["id"],
                Agendamento.data >= inicio_mes
            ).count(),
            "faturamento": float(db.session.query(
                db.func.sum(Agendamento.preco)
            ).filter(
                Agendamento.barbeiro == barbeiro["id"],
                Agendamento.data >= inicio_mes,
                Agendamento.status == StatusAgendamento.CONCLUIDO
            ).scalar() or 0)
        }
        relatorio["por_barbeiro"].append(dados)
    
     # Por serviço
    for servico in SERVICOS_DISPONIVEIS:
        dados = {
            "servico": servico["nome"],
            "quantidade": Agendamento.query.filter(
                Agendamento.servico == servico["id"],
                Agendamento.data >= inicio_mes
            ).count(),
            "faturamento": float(db.session.query(
                db.func.sum(Agendamento.preco)
            ).filter(
                Agendamento.servico == servico["id"],
                Agendamento.data >= inicio_mes,
                Agendamento.status == StatusAgendamento.CONCLUIDO
            ).scalar() or 0)
        }
        relatorio["por_servico"].append(dados)
    
    # Por dia da semana
    dias_semana = ['Segunda', 'Terça', 'Quarta', 'Quinta', 'Sexta', 'Sábado', 'Domingo']
    for i, dia in enumerate(dias_semana):
        # SQLite: strftime('%w', data) retorna 0=domingo, 1=segunda...
        # Ajustamos para 0=segunda
        sqlite_day = (i + 1) % 7
        count = db.session.query(db.func.count(Agendamento.id)).filter(
            Agendamento.data >= inicio_mes,
            db.func.strftime('%w', Agendamento.data) == str(sqlite_day)
        ).scalar() or 0
        
        relatorio["por_dia_semana"].append({
            "dia": dia,
            "agendamentos": count
        })
    
    log_audit("admin_export_relatorio")
    
    return jsonify(relatorio)


# ============================================================
# API - LOGS E AUDITORIA
# ============================================================

@app.route("/api/admin/logs")
@admin_required
def admin_logs():
    """Lista logs de auditoria"""
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    action = request.args.get("action")
    user_type = request.args.get("user_type")
    data_inicio = request.args.get("data_inicio")
    data_fim = request.args.get("data_fim")
    
    query = AuditLog.query
    
    if action:
        query = query.filter(AuditLog.action.ilike(f"%{action}%"))
    
    if user_type:
        query = query.filter_by(user_type=user_type)
    
    if data_inicio:
        try:
            data_ini = datetime.strptime(data_inicio, "%Y-%m-%d")
            query = query.filter(AuditLog.timestamp >= data_ini)
        except ValueError:
            pass
    
    if data_fim:
        try:
            data_f = datetime.strptime(data_fim, "%Y-%m-%d") + timedelta(days=1)
            query = query.filter(AuditLog.timestamp < data_f)
        except ValueError:
            pass
    
    query = query.order_by(AuditLog.timestamp.desc())
    
    per_page = min(per_page, 100)
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    
    logs = []
    for log in pagination.items:
        logs.append({
            "id": log.id,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            "user_type": log.user_type,
            "user_id": log.user_id,
            "action": log.action,
            "resource": log.resource,
            "resource_id": log.resource_id,
            "details": log.details,
            "ip_address": log.ip_address
        })
    
    return jsonify({
        "total": pagination.total,
        "pages": pagination.pages,
        "page": page,
        "per_page": per_page,
        "logs": logs
    })


# ============================================================
# API - CONFIGURAÇÕES ADMIN
# ============================================================

@app.route("/api/admin/admins")
@admin_required
def admin_list_admins():
    """Lista administradores"""
    admins = Admin.query.order_by(Admin.id).all()
    
    return jsonify([{
        "id": a.id,
        "username": a.username,
        "email": a.email,
        "nome": a.nome,
        "ativo": a.ativo,
        "ultimo_login": a.ultimo_login.isoformat() if a.ultimo_login else None,
        "criado_em": a.criado_em.isoformat() if a.criado_em else None
    } for a in admins])


@app.route("/api/admin/admins", methods=["POST"])
@admin_required
def admin_create_admin():
    """Cria novo administrador"""
    data = request.json or {}
    
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""
    email = (data.get("email") or "").strip().lower()
    nome = (data.get("nome") or "").strip()
    
    errors = {}
    
    if not username or len(username) < 3:
        errors["username"] = "Username deve ter pelo menos 3 caracteres"
    elif not re.match(r'^[a-z0-9_]+$', username):
        errors["username"] = "Username deve conter apenas letras, números e underscore"
    elif Admin.query.filter_by(username=username).first():
        errors["username"] = "Username já existe"
    
    if not password or len(password) < 6:
        errors["password"] = "Senha deve ter pelo menos 6 caracteres"
    
    if email and not valida_email(email):
        errors["email"] = "E-mail inválido"
    
    if errors:
        return jsonify({"error": "Dados inválidos", "errors": errors}), 400
    
    try:
        admin = Admin(
            username=username,
            email=email or None,
            nome=nome or None
        )
        admin.set_password(password)
        
        db.session.add(admin)
        db.session.commit()
        
        log_audit("admin_create_admin", "admin", admin.id, f"Criado por: {g.admin.username}")
        
        return jsonify({
            "ok": True,
            "message": "Administrador criado com sucesso",
            "id": admin.id
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao criar admin: {e}")
        return jsonify({"error": "Erro ao criar administrador"}), 500


@app.route("/api/admin/admins/<int:id>", methods=["PUT"])
@admin_required
def admin_update_admin(id):
    """Atualiza administrador"""
    admin = Admin.query.get_or_404(id)
    data = request.json or {}
    
    if "email" in data:
        email = (data["email"] or "").strip().lower()
        if email and not valida_email(email):
            return jsonify({"error": "E-mail inválido"}), 400
        admin.email = email or None
    
    if "nome" in data:
        admin.nome = (data["nome"] or "").strip() or None
    
    if "ativo" in data:
        # Não pode desativar a si mesmo
        if id == g.admin.id and not data["ativo"]:
            return jsonify({"error": "Você não pode desativar sua própria conta"}), 400
        admin.ativo = bool(data["ativo"])
    
    if "password" in data and data["password"]:
        if len(data["password"]) < 6:
            return jsonify({"error": "Senha deve ter pelo menos 6 caracteres"}), 400
        admin.set_password(data["password"])
    
    try:
        db.session.commit()
        log_audit("admin_update_admin", "admin", id)
        return jsonify({"ok": True, "message": "Administrador atualizado"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao atualizar admin: {e}")
        return jsonify({"error": "Erro ao atualizar administrador"}), 500


@app.route("/api/admin/admins/<int:id>", methods=["DELETE"])
@admin_required
def admin_delete_admin(id):
    """Exclui administrador"""
    if id == g.admin.id:
        return jsonify({"error": "Você não pode excluir sua própria conta"}), 400
    
    admin = Admin.query.get_or_404(id)
    
    # Verifica se é o último admin ativo
    ativos = Admin.query.filter_by(ativo=True).count()
    if ativos <= 1 and admin.ativo:
        return jsonify({"error": "Não é possível excluir o último administrador ativo"}), 400
    
    try:
        db.session.delete(admin)
        db.session.commit()
        log_audit("admin_delete_admin", "admin", id, f"Excluído por: {g.admin.username}")
        return jsonify({"ok": True, "message": "Administrador excluído"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao excluir admin: {e}")
        return jsonify({"error": "Erro ao excluir administrador"}), 500


# ============================================================
# API - UTILITÁRIOS
# ============================================================

@app.route("/api/validar-cpf")
def api_validar_cpf():
    """Valida CPF e verifica se já existe"""
    cpf = only_digits(request.args.get("cpf", ""))
    
    if not cpf:
        return jsonify({"valid": False, "message": "CPF não informado"})
    
    if not valida_cpf(cpf):
        return jsonify({"valid": False, "message": "CPF inválido"})
    
    existe = Cliente.query.filter_by(cpf=cpf).first()
    if existe:
        return jsonify({"valid": False, "message": "CPF já cadastrado"})
    
    return jsonify({"valid": True, "message": "CPF válido"})


@app.route("/api/validar-email")
def api_validar_email():
    """Valida e-mail e verifica se já existe"""
    email = (request.args.get("email", "") or "").lower().strip()
    
    if not email:
        return jsonify({"valid": True, "message": "E-mail não informado"})
    
    if not valida_email(email):
        return jsonify({"valid": False, "message": "E-mail inválido"})
    
    existe = Cliente.query.filter_by(email=email).first()
    if existe:
        return jsonify({"valid": False, "message": "E-mail já cadastrado"})
    
    return jsonify({"valid": True, "message": "E-mail válido"})


@app.route("/api/buscar-cep/<cep>")
def api_buscar_cep(cep):
    """Busca endereço pelo CEP (usando ViaCEP)"""
    import urllib.request
    import json
    
    cep = only_digits(cep)
    
    if len(cep) != 8:
        return jsonify({"error": "CEP inválido"}), 400
    
    try:
        url = f"https://viacep.com.br/ws/{cep}/json/"
        with urllib.request.urlopen(url, timeout=5) as response:
            data = json.loads(response.read().decode())
        
        if data.get("erro"):
            return jsonify({"error": "CEP não encontrado"}), 404
        
        return jsonify({
            "cep": data.get("cep", "").replace("-", ""),
            "logradouro": data.get("logradouro", ""),
            "complemento": data.get("complemento", ""),
            "bairro": data.get("bairro", ""),
            "cidade": data.get("localidade", ""),
            "estado": data.get("uf", ""),
            "endereco_completo": f"{data.get('logradouro', '')}, {data.get('bairro', '')} - {data.get('localidade', '')}/{data.get('uf', '')}"
        })
        
    except Exception as e:
        logger.error(f"Erro ao buscar CEP: {e}")
        return jsonify({"error": "Erro ao buscar CEP"}), 500


@app.route("/api/health")
def api_health():
    """Health check da aplicação"""
    try:
        # Testa conexão com banco
        db.session.execute(db.text("SELECT 1"))
        db_status = "ok"
    except Exception as e:
        db_status = f"error: {str(e)}"
    
    return jsonify({
        "status": "ok" if db_status == "ok" else "degraded",
        "timestamp": datetime.utcnow().isoformat(),
        "database": db_status,
        "version": "1.0.0"
    })


# ============================================================
# DEBUG (apenas desenvolvimento)
# ============================================================

if app.debug:
    @app.route("/debug/info")
    def debug_info():
        """Informações de debug"""
        return jsonify({
            "BASE_DIR": BASE_DIR,
            "DB_PATH": DB_PATH,
            "DB_exists": os.path.exists(DB_PATH),
            "session": {
                "client_id": session.get("client_id"),
                "admin_id": session.get("admin_id"),
                "admin_logged": session.get("admin_logged")
            },
            "config": {
                "ENV": app.config.get("ENV"),
                "DEBUG": app.debug
            }
        })
    
    @app.route("/debug/reset-db", methods=["POST"])
    def debug_reset_db():
        """Reseta banco de dados (APENAS DEBUG!)"""
        db.drop_all()
        db.create_all()
        
        # Cria admin padrão
        admin = Admin(username="admin", nome="Administrador")
        admin.set_password("admin123")
        db.session.add(admin)
        db.session.commit()
        
        return jsonify({"ok": True, "message": "Banco resetado"})


# ============================================================
# CLI COMMANDS
# ============================================================

@app.cli.command("initdb")
def initdb_command():
    """Inicializa o banco de dados"""
    db.create_all()
    
    # Cria admin padrão se não existir
    admin_user = os.getenv('ADMIN_USER', 'admin')
    admin_pass = os.getenv('ADMIN_PASS', 'admin123')
    admin_email = os.getenv('ADMIN_EMAIL')
    
    if not Admin.query.filter_by(username=admin_user).first():
        admin = Admin(
            username=admin_user,
            email=admin_email,
            nome="Administrador"
        )
        admin.set_password(admin_pass)
        db.session.add(admin)
        db.session.commit()
        logger.info(f"Admin criado: {admin_user}")
    
    logger.info("Banco de dados inicializado com sucesso!")


@app.cli.command("create-admin")
def create_admin_command():
    """Cria um novo administrador via CLI"""
    import click
    
    username = click.prompt("Username", type=str)
    email = click.prompt("E-mail (opcional)", type=str, default="")
    nome = click.prompt("Nome (opcional)", type=str, default="")
    password = click.prompt("Senha", type=str, hide_input=True, confirmation_prompt=True)
    
    if Admin.query.filter_by(username=username).first():
        click.echo(f"Erro: Username '{username}' já existe!")
        return
    
    if len(password) < 6:
        click.echo("Erro: Senha deve ter pelo menos 6 caracteres!")
        return
    
    admin = Admin(
        username=username,
        email=email or None,
        nome=nome or None
    )
    admin.set_password(password)
    
    db.session.add(admin)
    db.session.commit()
    
    click.echo(f"Administrador '{username}' criado com sucesso!")


@app.cli.command("list-admins")
def list_admins_command():
    """Lista todos os administradores"""
    import click
    
    admins = Admin.query.all()
    
    if not admins:
        click.echo("Nenhum administrador cadastrado.")
        return
    
    click.echo("\n=== Administradores ===")
    for admin in admins:
        status = "✓ Ativo" if admin.ativo else "✗ Inativo"
        click.echo(f"  [{admin.id}] {admin.username} - {admin.nome or 'Sem nome'} ({status})")
    click.echo("")


@app.cli.command("reset-admin-password")
def reset_admin_password_command():
    """Reseta senha de um administrador"""
    import click
    
    username = click.prompt("Username do admin", type=str)
    
    admin = Admin.query.filter_by(username=username).first()
    if not admin:
        click.echo(f"Erro: Admin '{username}' não encontrado!")
        return
    
    password = click.prompt("Nova senha", type=str, hide_input=True, confirmation_prompt=True)
    
    if len(password) < 6:
        click.echo("Erro: Senha deve ter pelo menos 6 caracteres!")
        return
    
    admin.set_password(password)
    db.session.commit()
    
    click.echo(f"Senha do admin '{username}' alterada com sucesso!")


@app.cli.command("stats")
def stats_command():
    """Mostra estatísticas do sistema"""
    import click
    
    hoje = datetime.utcnow().date()
    inicio_mes = hoje.replace(day=1)
    
    total_clientes = Cliente.query.filter_by(ativo=True).count()
    total_agendamentos = Agendamento.query.count()
    agendamentos_hoje = Agendamento.query.filter(Agendamento.data == hoje).count()
    agendamentos_mes = Agendamento.query.filter(Agendamento.data >= inicio_mes).count()
    
    faturamento_mes = db.session.query(
        db.func.sum(Agendamento.preco)
    ).filter(
        Agendamento.data >= inicio_mes,
        Agendamento.status == StatusAgendamento.CONCLUIDO
    ).scalar() or 0
    
    click.echo("\n" + "=" * 40)
    click.echo("       ESTATÍSTICAS BARBLAB")
    click.echo("=" * 40)
    click.echo(f"  Clientes ativos:        {total_clientes}")
    click.echo(f"  Total de agendamentos:  {total_agendamentos}")
    click.echo(f"  Agendamentos hoje:      {agendamentos_hoje}")
    click.echo(f"  Agendamentos no mês:    {agendamentos_mes}")
    click.echo(f"  Faturamento do mês:     R$ {float(faturamento_mes):.2f}")
    click.echo("=" * 40 + "\n")


@app.cli.command("cleanup-logs")
def cleanup_logs_command():
    """Remove logs de auditoria antigos (mais de 90 dias)"""
    import click
    
    dias = click.prompt("Remover logs mais antigos que (dias)", type=int, default=90)
    
    cutoff = datetime.utcnow() - timedelta(days=dias)
    
    count = AuditLog.query.filter(AuditLog.timestamp < cutoff).count()
    
    if count == 0:
        click.echo("Nenhum log antigo para remover.")
        return
    
    if click.confirm(f"Remover {count} logs anteriores a {cutoff.strftime('%d/%m/%Y')}?"):
        AuditLog.query.filter(AuditLog.timestamp < cutoff).delete()
        db.session.commit()
        click.echo(f"{count} logs removidos com sucesso!")
    else:
        click.echo("Operação cancelada.")


@app.cli.command("backup-db")
def backup_db_command():
    """Cria backup do banco de dados"""
    import click
    import shutil
    
    if not os.path.exists(DB_PATH):
        click.echo("Erro: Banco de dados não encontrado!")
        return
    
    backup_dir = os.path.join(BASE_DIR, "backups")
    os.makedirs(backup_dir, exist_ok=True)
    
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(backup_dir, f"barblab_backup_{timestamp}.db")
    
    shutil.copy2(DB_PATH, backup_path)
    
    click.echo(f"Backup criado: {backup_path}")


@app.cli.command("seed-demo")
def seed_demo_command():
    """Popula banco com dados de demonstração"""
    import click
    from random import choice, randint
    
    if not click.confirm("Isso irá adicionar dados de demonstração. Continuar?"):
        return
    
    # Nomes de exemplo
    nomes = [
        "João Silva", "Pedro Santos", "Carlos Oliveira", "Lucas Souza",
        "Marcos Lima", "Rafael Costa", "Bruno Almeida", "Felipe Rodrigues",
        "André Ferreira", "Gustavo Martins", "Ricardo Pereira", "Fernando Gomes"
    ]
    
    # Cria clientes de demonstração
    clientes_criados = 0
    for i, nome in enumerate(nomes):
        cpf = f"{randint(100,999)}{randint(100,999)}{randint(100,999)}{randint(10,99)}"
        
        # Valida CPF gerado (simplificado para demo)
        if Cliente.query.filter_by(cpf=cpf).first():
            continue
        
        cliente = Cliente(
            nome=nome,
            cpf=cpf,
            email=f"demo{i+1}@exemplo.com",
            telefone=f"11{randint(90000,99999)}{randint(1000,9999)}"
        )
        cliente.set_password("demo123")
        
        db.session.add(cliente)
        clientes_criados += 1
    
    db.session.commit()
    click.echo(f"{clientes_criados} clientes de demonstração criados.")
    
    # Cria agendamentos de demonstração
    clientes = Cliente.query.limit(10).all()
    agendamentos_criados = 0
    
    for cliente in clientes:
        # Cria 1-3 agendamentos por cliente
        for _ in range(randint(1, 3)):
            data_ag = datetime.utcnow().date() + timedelta(days=randint(1, 30))
            
            # Pula domingos
            if data_ag.weekday() == 6:
                continue
            
            horario = datetime.strptime(f"{randint(9,18)}:00", "%H:%M").time()
            servico = choice(SERVICOS_DISPONIVEIS)
            barbeiro = choice(BARBEIROS)
            
            # Verifica se horário está disponível
            existe = Agendamento.query.filter_by(
                data=data_ag,
                horario=horario,
                barbeiro=barbeiro["id"]
            ).first()
            
            if existe:
                continue
            
            agendamento = Agendamento(
                cliente_id=cliente.id,
                servico=servico["id"],
                barbeiro=barbeiro["id"],
                data=data_ag,
                horario=horario,
                preco=servico["preco"],
                duracao_minutos=servico["duracao"],
                status=choice([StatusAgendamento.PENDENTE, StatusAgendamento.CONFIRMADO])
            )
            
            db.session.add(agendamento)
            agendamentos_criados += 1
    
    db.session.commit()
    click.echo(f"{agendamentos_criados} agendamentos de demonstração criados.")
    click.echo("\nDados de demonstração criados com sucesso!")
    click.echo("Login demo: CPF de qualquer cliente / Senha: demo123")


# ============================================================
# INICIALIZAÇÃO
# ============================================================

def create_app():
    """Factory function para criar a aplicação"""
    with app.app_context():
        # Cria tabelas se não existirem
        if not os.path.exists(DB_PATH):
            db.create_all()
            logger.info("Banco de dados criado automaticamente.")
            
            # Cria admin padrão
            admin_user = os.getenv('ADMIN_USER', 'admin')
            admin_pass = os.getenv('ADMIN_PASS', 'admin123')
            
            if not Admin.query.filter_by(username=admin_user).first():
                admin = Admin(username=admin_user, nome="Administrador")
                admin.set_password(admin_pass)
                db.session.add(admin)
                db.session.commit()
                logger.info(f"Admin padrão criado: {admin_user}")
    
    return app


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    logger.info(f"BASE_DIR: {BASE_DIR}")
    logger.info(f"DB_PATH: {DB_PATH}")
    logger.info(f"DB EXISTS: {os.path.exists(DB_PATH)}")
    
    # Inicializa aplicação
    create_app()
    
    # Modo de execução
    debug_mode = os.getenv("FLASK_DEBUG", "true").lower() == "true"
    host = os.getenv("FLASK_HOST", "127.0.0.1")
    port = int(os.getenv("FLASK_PORT", 5000))
    
    logger.info(f"Iniciando servidor em {host}:{port} (debug={debug_mode})")
    
    app.run(
        host=host,
        port=port,
        debug=debug_mode
    )
