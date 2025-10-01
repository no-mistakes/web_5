import random, re
from flask import Flask, render_template, request, redirect, url_for
from faker import Faker

from flask import session, flash
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)

from datetime import datetime
from typing import Optional
import json
from flask import jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

from functools import wraps
from flask import Response
from sqlalchemy import event

fake = Faker()

app = Flask(__name__)
application = app
app.config['SECRET_KEY'] = app.config.get('SECRET_KEY') or 'dev-secret'
app.config.setdefault("SQLALCHEMY_DATABASE_URI", "sqlite:///app.db")
app.config.setdefault("SQLALCHEMY_TRACK_MODIFICATIONS", False)
db = SQLAlchemy(app)

images_ids = ['7d4e9175-95ea-4c5f-8be5-92a6b708bb3c',
              '2d2ab7df-cdbc-48a8-a936-35bba702def5',
              '6e12f3de-d5fd-4ebb-855b-8cbc485278b7',
              'afc2cfe7-5cac-4b80-9b9a-d5c65ef0c728',
              'cab5b7f2-774e-4884-a200-0c0180fa777f']

def generate_comments(replies=True):
    comments = []
    for i in range(random.randint(1, 3)):
        comment = { 'author': fake.name(), 'text': fake.text() }
        if replies:
            comment['replies'] = generate_comments(replies=False)
        comments.append(comment)
    return comments

def generate_post(i):
    return {
        'title': fake.sentence(nb_words=random.randint(2, 6)).rstrip('.'),
        'text': fake.paragraph(nb_sentences=100),
        'author': fake.name(),
        'date': fake.date_time_between(start_date='-2y', end_date='now'),
        'image_id': f'{images_ids[i]}.jpg',
        'comments': generate_comments()
    }

posts_list = sorted([generate_post(i) for i in range(5)], key=lambda p: p['date'], reverse=True)

# ----------- Комментарии
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/posts')
def posts():
    return render_template('posts.html', title='Посты', posts=posts_list)

@app.route('/posts/<int:index>', methods=['GET', 'POST'])
def post(index):
    p = posts_list[index]
    if request.method == 'POST':
        text = request.form.get('text', '').strip()
        if text:
            p['comments'].insert(0, {'author': 'Гость', 'text': text, 'replies': []})
        return redirect(url_for('post', index=index))
    return render_template('post.html', title=p['title'], post=p)

@app.route('/about')
def about():
    return render_template('about.html', title='Об авторе')

# ----------- Данные
@app.route('/show_url')
def show_url():
    return render_template('show_url.html', params=request.args)

@app.route('/show_headers')
def show_headers():
    return render_template('show_headers.html', headers=request.headers)

@app.route('/show_cookies')
def show_cookies():
    return render_template('show_cookies.html', cookies=request.cookies)

@app.route('/login', methods=['GET', 'POST'])
def login():
    username = password = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
    return render_template('login.html', username=username, password=password)

# ----------- Телефон
ALLOWED_CHARS_RE = re.compile(r'^[0-9 ()+\-\.]*$')

def normalize_phone(raw: str):
    if not ALLOWED_CHARS_RE.fullmatch(raw):
        return None, 'Недопустимый ввод. В номере телефона встречаются недопустимые символы.'
    digits = re.sub(r'\D', '', raw)
    starts_like_11 = raw.strip().startswith('+7') or raw.strip().startswith('8')
    if not (len(digits) in (10, 11)):
        return None, 'Недопустимый ввод. Неверное количество цифр.'
    if len(digits) == 11:
        if starts_like_11 or digits.startswith('7') or digits.startswith('8'):
            digits = digits[-10:]
        else:
            return None, 'Недопустимый ввод. Неверное количество цифр.'
    formatted = f"8-{digits[0:3]}-{digits[3:6]}-{digits[6:8]}-{digits[8:10]}"
    return formatted, None

@app.route('/phone', methods=['GET', 'POST'])
def phone():
    error = None
    formatted = None
    number = ''
    if request.method == 'POST':
        number = request.form.get('phone', '')
        formatted, error = normalize_phone(number)
    return render_template('phone.html', error=error, formatted=formatted, number=number)

# ----------- Фильтр Лабораторной 2
@app.route('/lab2')
def lab2():
    return render_template('lab2.html', title='ЛР2 · Навигация')

@app.route('/set_test_cookie')
def set_test_cookie():
    resp = redirect(url_for('show_cookies'))
    resp.set_cookie('sample', '12345')
    return resp

login_manager = LoginManager(app)
login_manager.login_view = 'auth_login'
login_manager.login_message = 'Требуется вход.'

# ----------- Пользователь в памяти
class User(UserMixin):
    def __init__(self, id_, login):
        self.id = id_
        self.login = login

# ----------- Пользователи в памяти
USERS = {'user': {'id': 1, 'password': 'qwerty'}}

@login_manager.user_loader
def load_user(user_id: str):
    for login, data in USERS.items():
        if str(data['id']) == str(user_id):
            return User(data['id'], login)
    return None

# ----------- Счет посещений
@app.route('/counter')
def counter():
    session['visits'] = session.get('visits', 0) + 1
    return render_template('counter.html', title='Счётчик', visits=session['visits'])

# ----------- Запомнить меня
@app.route('/auth/login', methods=['GET', 'POST'])
def auth_login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        remember = bool(request.form.get('remember'))
        rec = USERS.get(username)
        if rec and rec['password'] == password:
            user = User(rec['id'], username)
            login_user(user, remember=remember)
            flash('Вход выполнен', 'success')
            next_url = request.args.get('next') or url_for('index')
            return redirect(next_url)
        flash('Неверный логин или пароль', 'danger')
    return render_template('auth_login.html', title='Вход')

@app.route('/auth/logout')
@login_required
def auth_logout():
    logout_user()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))

# ----------- Секрет
@app.route('/secret')
@login_required
def secret():
    return render_template('secret.html', title='Секретная')

# ----------- Модели БД
class Role(db.Model):
    __tablename__ = "roles"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=True)

class Account(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(64), nullable=False, unique=True, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    last_name = db.Column(db.String(64), nullable=True)
    first_name = db.Column(db.String(64), nullable=False)
    middle_name = db.Column(db.String(64), nullable=True)
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    role = db.relationship("Role", backref="users")

    @property
    def is_authenticated(self): return True
    @property
    def is_active(self): return True
    @property
    def is_anonymous(self): return False
    def get_id(self): return str(self.id)

    @property
    def fio(self):
        parts = [p for p in [self.last_name, self.first_name, self.middle_name] if p]
        return " ".join(parts) if parts else "(ФИО не указано)"

    def set_password(self, raw): self.password_hash = generate_password_hash(raw)
    def check_password(self, raw): return check_password_hash(self.password_hash, raw)

# ----------- Инициализация
@app.before_request
def _lr4_ensure_db_and_seed():
    if getattr(app, "_lr4_ready", False):
        return
    db.create_all()
    if Role.query.count() == 0:
        db.session.add_all([
            Role(name="Администратор", description="Полные права"),
            Role(name="Пользователь", description="Обычный доступ")
        ])
        db.session.commit()
    if Account.query.count() == 0:
        admin_role = Role.query.filter_by(name="Администратор").first()
        admin = Account(login="admin", first_name="Админ", last_name="Системный", role_id=admin_role.id)
        admin.set_password("Admin1234")
        db.session.add(admin)
        db.session.commit()
    app._lr4_ready = True

LOGIN_RE = re.compile(r"^[A-Za-z0-9]{5,}$")
ALLOWED_PUNCT = r"""~ ! ? @ # $ % ^ & * _ - + ( ) [ ] { } > < / \ | " ' . , : ;"""
PUNCT_CLASS = re.escape(ALLOWED_PUNCT)
PASSWORD_RE = re.compile(
    rf"^(?=.*[a-zа-я])(?=.*[A-ZА-Я])(?=.*\d)[A-Za-zА-Яа-я\d{PUNCT_CLASS}]{{8,128}}$"
)

# ----------- Проверка форм
def _v_create(form):
    errors = {}
    login = (form.get("login") or "").strip()
    password = form.get("password") or ""
    first_name = (form.get("first_name") or "").strip()

    if not login: errors["login"] = "Поле не может быть пустым"
    elif not LOGIN_RE.match(login): errors["login"] = "Только латиница/цифры, длина ≥ 5"
    elif Account.query.filter_by(login=login).first(): errors["login"] = "Логин уже занят"

    if not password: errors["password"] = "Поле не может быть пустым"
    elif " " in password: errors["password"] = "Без пробелов"
    elif not PASSWORD_RE.match(password):
        errors["password"] = ("8–128, ≥1 строчная и ≥1 заглавная буквы, ≥1 цифра, "
                              "латиница/кириллица, допустимые знаки: " + ALLOWED_PUNCT)
    if not first_name: errors["first_name"] = "Поле не может быть пустым"

    role_id = form.get("role_id")
    if role_id:
        try:
            rid = int(role_id)
            if rid != 0 and not db.session.get(Role, rid):
                errors["role_id"] = "Роль не существует"
        except ValueError:
            errors["role_id"] = "Некорректная роль"
    return errors

def _v_edit(form):
    errors = {}
    first_name = (form.get("first_name") or "").strip()
    if not first_name: errors["first_name"] = "Поле не может быть пустым"
    role_id = form.get("role_id")
    if role_id:
        try:
            rid = int(role_id)
            if rid != 0 and not db.session.get(Role, rid):
                errors["role_id"] = "Роль не существует"
        except ValueError:
            errors["role_id"] = "Некорректная роль"
    return errors

def _v_change_pwd(user: Account, old_pwd, new_pwd, rep_pwd):
    errors = {}
    if not old_pwd or not user.check_password(old_pwd):
        errors["old_password"] = "Неверный старый пароль"
    if not new_pwd: errors["new_password"] = "Поле не может быть пустым"
    elif " " in new_pwd: errors["new_password"] = "Без пробелов"
    elif not PASSWORD_RE.match(new_pwd):
        errors["new_password"] = ("8–128, ≥1 строчная и ≥1 заглавная буквы, ≥1 цифра, "
                                  "латиница/кириллица, допустимые знаки: " + ALLOWED_PUNCT)
    if new_pwd != rep_pwd: errors["repeat_password"] = "Пароли не совпадают"
    return errors

# ----------- Аутентификация из БД
@login_manager.user_loader
def _lr4_load_user(user_id: str) -> Optional[Account]:
    try:
        return db.session.get(Account, int(user_id))
    except Exception:
        return None

# ----------- /auth/login
@app.before_request
def _lr4_intercept_login():
    if request.endpoint == "auth_login" and request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        acc = Account.query.filter_by(login=username).first()
        if acc and acc.check_password(password):
            remember = bool(request.form.get("remember"))
            login_user(acc, remember=remember)
            flash("Вход выполнен", "success")
            next_url = request.args.get('next') or url_for('index')
            return redirect(next_url)

# ----------- API для таблицы пользователей
@app.get("/users.json")
def users_json():
    data = []
    for i, u in enumerate(Account.query.order_by(Account.id.asc()).all(), start=1):
        data.append({
            "n": i,
            "id": u.id,
            "fio": u.fio,
            "role": (u.role.name if u.role else "(нет роли)")
        })
    return jsonify(data)

# ----------- Пользовательский интерфейс для редактирования/просмотра/удаления пользователя
@app.get("/users/<int:user_id>")
def users_view(user_id: int):
    user = db.session.get(Account, user_id)
    if not user: return ("Не найдено", 404)
    return render_template("user_view.html", user=user, title="Просмотр пользователя")

@app.route("/users/create", methods=["GET", "POST"])
@login_required
def users_create():
    roles = Role.query.order_by(Role.name).all()
    if request.method == "GET":
        return render_template("user_form_create.html", roles=roles, values={}, errors={}, title="Создание пользователя")
    form = request.form
    errors = _v_create(form)
    if errors:
        flash("Исправьте ошибки формы", "danger")
        return render_template("user_form_create.html", roles=roles, values=form, errors=errors, title="Создание пользователя")
    try:
        role_id = int(form.get("role_id") or 0) or None
        u = Account(
            login=(form.get("login") or "").strip(),
            first_name=(form.get("first_name") or "").strip(),
            last_name=(form.get("last_name") or "").strip() or None,
            middle_name=(form.get("middle_name") or "").strip() or None,
            role_id=role_id
        )
        u.set_password(form.get("password") or "")
        db.session.add(u)
        db.session.commit()
        flash("Пользователь создан", "success")
        return redirect(url_for("index"))
    except Exception as e:
        db.session.rollback()
        flash(f"Ошибка записи в БД: {e}", "danger")
        return render_template("user_form_create.html", roles=roles, values=form, errors={}, title="Создание пользователя")

@app.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
def users_edit(user_id: int):
    user = db.session.get(Account, user_id)
    if not user: return ("Не найдено", 404)
    roles = Role.query.order_by(Role.name).all()
    if request.method == "GET":
        values = dict(
            first_name=user.first_name or "",
            last_name=user.last_name or "",
            middle_name=user.middle_name or "",
            role_id=str(user.role_id or 0),
        )
        return render_template("user_form_edit.html", roles=roles, values=values, errors={}, title="Редактирование пользователя")
    form = request.form
    errors = _v_edit(form)
    if errors:
        flash("Исправьте ошибки формы", "danger")
        return render_template("user_form_edit.html", roles=roles, values=form, errors=errors, title="Редактирование пользователя")
    try:
        user.first_name = (form.get("first_name") or "").strip()
        user.last_name = (form.get("last_name") or "").strip() or None
        user.middle_name = (form.get("middle_name") or "").strip() or None
        user.role_id = int(form.get("role_id") or 0) or None
        db.session.commit()
        flash("Пользователь обновлён", "success")
        return redirect(url_for("index"))
    except Exception as e:
        db.session.rollback()
        flash(f"Ошибка записи в БД: {e}", "danger")
        return render_template("user_form_edit.html", roles=roles, values=form, errors={}, title="Редактирование пользователя")

@app.post("/users/<int:user_id>/delete")
@login_required
def users_delete(user_id: int):
    user = db.session.get(Account, user_id)
    if not user: 
        flash("Пользователь не найден", "danger")
        return redirect(url_for("index"))
    try:
        db.session.delete(user)
        db.session.commit()
        flash("Пользователь удалён", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Ошибка удаления: {e}", "danger")
    return redirect(url_for("index"))

# ----------- Смена пароля
@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "GET":
        return render_template("change_password.html", errors={}, values={}, title="Смена пароля")
    old = request.form.get("old_password") or ""
    new = request.form.get("new_password") or ""
    rep = request.form.get("repeat_password") or ""
    user = db.session.get(Account, int(current_user.get_id()))
    errors = _v_change_pwd(user, old, new, rep)
    if errors:
        flash("Исправьте ошибки формы", "danger")
        return render_template("change_password.html", errors=errors, values=request.form, title="Смена пароля")
    try:
        user.set_password(new)
        db.session.commit()
        flash("Пароль изменён", "success")
        return redirect(url_for("index"))
    except Exception as e:
        db.session.rollback()
        flash(f"Ошибка обновления пароля: {e}", "danger")
        return render_template("change_password.html", errors={}, values=request.form, title="Смена пароля")

# ----------- Проверка прав
def check_rights(*allowed_roles: str):
    def outer(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("У вас недостаточно прав для доступа к данной странице.")
                return redirect(url_for("index"))
            role_name = getattr(getattr(current_user, "role", None), "name", None)
            if role_name not in allowed_roles:
                flash("У вас недостаточно прав для доступа к данной странице.")
                return redirect(url_for("index"))
            return view(*args, **kwargs)
        return wrapped
    return outer

# ----------- Модель посещений
class VisitLog(db.Model):
    __tablename__ = "visit_logs"
    id = db.Column(db.Integer, primary_key=True)
    path = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user = db.relationship("Account", backref="visit_logs", lazy="joined")

# ----------- Таблицы журнала
@app.before_request
def _lr5_ensure_visit_table():
    if getattr(app, "_lr5_visit_ready", False):
        return
    try:
        db.create_all()
    finally:
        app._lr5_visit_ready = True

# ----------- Логирование посещений
@app.before_request
def _lr5_log_visit():
    p = request.path or "/"
    if p.startswith("/static") or p == "/favicon.ico":
        return
    try:
        uid = int(current_user.get_id()) if current_user.is_authenticated else None
    except Exception:
        uid = None
    try:
        db.session.add(VisitLog(path=p[:100], user_id=uid))
        db.session.commit()
    except Exception:
        db.session.rollback()

# ----------- Странички
def _paginate(query, per_page: int = 20):
    page = max(int(request.args.get("page", 1)), 1)
    items = query.limit(per_page).offset((page - 1) * per_page).all()
    total = query.order_by(None).count()
    return items, page, per_page, total

# ----------- Журнал посещений
@app.get("/reports")
@check_rights("Администратор", "Пользователь")
def reports_index():
    q = db.session.query(VisitLog).order_by(VisitLog.created_at.desc())
    role_name = getattr(getattr(current_user, "role", None), "name", None)
    if role_name == "Пользователь":
        q = q.filter((VisitLog.user_id == current_user.id) | (VisitLog.user_id.is_(None)))
    items, page, per_page, total = _paginate(q, per_page=20)
    start = (page - 1) * per_page
    rows = []
    for i, v in enumerate(items, start=1):
        fio = v.user.fio if v.user else "Неаутентифицированный пользователь"
        rows.append({
            "n": start + i,
            "user": fio,
            "path": v.path,
            "dt": v.created_at.strftime("%d.%m.%Y %H:%M:%S"),
        })
    return render_template("index_reports.html", rows=rows, page=page, per_page=per_page, total=total)

# ----------- Отчёт по страницам
@app.get("/reports/by-page")
@check_rights("Администратор")
def reports_by_page():
    from sqlalchemy import func, desc
    q = (db.session.query(VisitLog.path, func.count(VisitLog.id).label("cnt"))
         .group_by(VisitLog.path).order_by(desc("cnt")))
    rows = [{"n": i + 1, "path": r.path, "cnt": r.cnt} for i, r in enumerate(q.all())]
    return render_template("by_page.html", rows=rows)

@app.get("/reports/by-page.csv")
@check_rights("Администратор")
def reports_by_page_csv():
    from sqlalchemy import func, desc
    q = (db.session.query(VisitLog.path, func.count(VisitLog.id).label("cnt"))
         .group_by(VisitLog.path).order_by(desc("cnt")))
    buf = ["№,Страница,Количество посещений"]
    for i, r in enumerate(q.all(), start=1):
        buf.append(f"{i},{r.path},{r.cnt}")
    data = ("\n".join(buf)).encode("utf-8-sig")
    return Response(
        data,
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=by_page.csv"}
    )

# ----------- Отчёт по пользователям
def _fio_parts(last, first, middle):
    parts = [p for p in [last, first, middle] if p]
    return " ".join(parts) if parts else "Неаутентифицированный пользователь"

@app.get("/reports/by-user")
@check_rights("Администратор")
def reports_by_user():
    from sqlalchemy import func, desc
    q = (db.session.query(VisitLog.user_id, func.count(VisitLog.id).label("cnt"))
         .group_by(VisitLog.user_id).order_by(desc("cnt")))
    users = {}
    for row in db.session.query(Account.id, Account.last_name, Account.first_name, Account.middle_name).all():
        users[row.id] = _fio_parts(row.last_name, row.first_name, row.middle_name)
    rows = []
    for i, r in enumerate(q.all(), start=1):
        name = users.get(r.user_id) if r.user_id is not None else "Неаутентифицированный пользователь"
        rows.append({"n": i, "user": name, "cnt": r.cnt})
    return render_template("by_user.html", rows=rows)

@app.get("/reports/by-user.csv")
@check_rights("Администратор")
def reports_by_user_csv():
    from sqlalchemy import func, desc
    q = (db.session.query(VisitLog.user_id, func.count(VisitLog.id).label("cnt"))
         .group_by(VisitLog.user_id).order_by(desc("cnt")))
    users = {}
    for row in db.session.query(Account.id, Account.last_name, Account.first_name, Account.middle_name).all():
        users[row.id] = _fio_parts(row.last_name, row.first_name, row.middle_name)
    buf = ["№,Пользователь,Количество посещений"]
    for i, r in enumerate(q.all(), start=1):
        name = users.get(r.user_id) if r.user_id is not None else "Неаутентифицированный пользователь"
        buf.append(f"{i},{name},{r.cnt}")
    data = ("\n".join(buf)).encode("utf-8-sig")
    return Response(
        data,
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=by_user.csv"}
    )

# -----------
@app.before_request
def _lr5_access_guard_users():
    ep = request.endpoint or ""
    role_name = getattr(getattr(current_user, "role", None), "name", None)

    if ep in ("users_create", "users_delete"):
        if not current_user.is_authenticated or role_name != "Администратор":
            flash("У вас недостаточно прав для доступа к данной странице.")
            return redirect(url_for("index"))

    if ep == "users_edit":
        if not current_user.is_authenticated:
            flash("У вас недостаточно прав для доступа к данной странице.")
            return redirect(url_for("index"))
        if role_name != "Администратор":
            uid = request.view_args.get("user_id") if request.view_args else None
            if uid is None or int(uid) != int(current_user.get_id()):
                flash("У вас недостаточно прав для доступа к данной странице.")
                return redirect(url_for("index"))

# -----------
@event.listens_for(Account, "before_update")
def _lr5_block_role_change_for_non_admin(mapper, connection, target):
    try:
        rn = getattr(getattr(current_user, "role", None), "name", None)
        cur_id = int(current_user.get_id()) if current_user.is_authenticated else None
    except Exception:
        rn, cur_id = None, None
    if rn != "Администратор" and target.id != cur_id:
        raise Exception("Недостаточно прав для изменения другого пользователя")
    if rn != "Администратор":
        state = db.inspect(target).attrs.role_id
        if state.history.has_changes():
            target.role_id = state.history.deleted[0] if state.history.deleted else target.role_id

@event.listens_for(db.session, "before_flush")
def _lr5_block_delete_for_non_admin(session, flush_context, instances):
    try:
        rn = getattr(getattr(current_user, "role", None), "name", None)
    except Exception:
        rn = None
    if rn != "Администратор":
        for obj in list(session.deleted):
            if isinstance(obj, Account):
                raise Exception("Недостаточно прав для удаления пользователя")
