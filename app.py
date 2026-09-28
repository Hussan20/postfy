import admin
import hmac
import os
import re
import secrets
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse

from flask import (Flask, Response, abort, flash, g, jsonify, redirect,
                   render_template, request, session, url_for)
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from markupsafe import Markup, escape
from sqlalchemy import func, inspect, or_, text
from sqlalchemy.orm import contains_eager, joinedload
from werkzeug.security import generate_password_hash, check_password_hash

# The templates folder is named "Templates" in this repo; name it explicitly so
# the app also works on case-sensitive filesystems (Linux, macOS, CI).
app = Flask(__name__, template_folder='Templates')


APP_VERSION = "Postfy-0.4_alpha"

app.config['UPLOAD_FOLDER'] = os.path.join(app.static_folder, 'profile_pics')
app.config['COVER_FOLDER'] = os.path.join(app.static_folder, 'cover_pics')
app.config['POST_IMAGE_FOLDER'] = os.path.join(app.static_folder, 'post_images')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['POSTS_PER_PAGE'] = 10
app.config['CSRF_ENABLED'] = True
# Set by tools/build_static.py when rendering the GitHub Pages demo.
app.config['STATIC_DEMO'] = os.environ.get('POSTFY_STATIC_DEMO') == '1'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

for folder in ('UPLOAD_FOLDER', 'COVER_FOLDER', 'POST_IMAGE_FOLDER'):
    os.makedirs(app.config[folder], exist_ok=True)

MAX_TITLE_LENGTH = 255
MAX_POST_LENGTH = 5000
MAX_COMMENT_LENGTH = 1000
MAX_MESSAGE_LENGTH = 2000
MAX_BIO_LENGTH = 160
USERNAME_RE = re.compile(r'^[a-z0-9_]{3,30}$')
RESERVED_USERNAMES = {'admin', 'administrator', 'postfy', 'support', 'root', 'system'}


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower(
           ) in app.config['ALLOWED_EXTENSIONS']


@app.context_processor
def inject_version():
    return dict(APP_VERSION=APP_VERSION)


app.secret_key = os.environ.get('SECRET_KEY', 'your_secret_key')

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Import admin module after app and db are created
admin.initialize_admin(app, db)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    profile_picture = db.Column(
        db.String(200), nullable=True, default='default.jpg')
    is_active = db.Column(db.Boolean, nullable=False,
                          default=True, server_default=text('1'))
    username = db.Column(db.String(30), unique=True, index=True)
    bio = db.Column(db.String(280))
    location = db.Column(db.String(100))
    website = db.Column(db.String(200))
    cover_picture = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def full_name(self):
        return f'{self.first_name} {self.last_name}'.strip()

    @property
    def handle(self):
        return self.username or f'user{self.id}'

    @property
    def initials(self):
        return ((self.first_name or '?')[:1] + (self.last_name or '')[:1]).upper()

    @property
    def avatar_hue(self):
        return (self.id or 0) * 47 % 360

    @property
    def avatar_url(self):
        if self.profile_picture and self.profile_picture != 'default.jpg':
            return url_for('static', filename='profile_pics/' + self.profile_picture)
        return None

    @property
    def cover_url(self):
        if self.cover_picture:
            return url_for('static', filename='cover_pics/' + self.cover_picture)
        return None

    @property
    def website_label(self):
        if not self.website:
            return ''
        return re.sub(r'^https?://(www\.)?', '', self.website).rstrip('/')

    def __repr__(self):
        return f'<User {self.first_name} {self.last_name}>'


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date_posted = db.Column(
        db.DateTime, default=datetime.utcnow)
    image = db.Column(db.String(200))
    updated_at = db.Column(db.DateTime)

    user = db.relationship('User', backref='posts', lazy=True)

    @property
    def image_url(self):
        if self.image:
            return url_for('static', filename='post_images/' + self.image)
        return None

    @property
    def is_edited(self):
        return bool(self.updated_at and self.date_posted and
                    self.updated_at - self.date_posted > timedelta(minutes=1))

    def __repr__(self):
        return f'<Post {self.title}>'


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    post = db.relationship('Post', backref=db.backref(
        'comments', lazy=True, cascade="all, delete-orphan"))
    user = db.relationship('User', backref=db.backref('comments', lazy=True))

    def __repr__(self):
        return f'<Comment {self.id} on Post {self.post_id} by User {self.user_id}>'


class Reaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reaction_type = db.Column(
        db.String(10), nullable=False)  # 'like' or 'dislike'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Add relationships for easier querying
    post = db.relationship('Post', backref=db.backref(
        'reactions', lazy=True, cascade="all, delete-orphan"))
    user = db.relationship('User', backref=db.backref('reactions', lazy=True))

    # Ensure a user can only have one reaction per post
    __table_args__ = (db.UniqueConstraint(
        'post_id', 'user_id', name='unique_user_post_reaction'),)

    def __repr__(self):
        return f'<Reaction {self.reaction_type} on Post {self.post_id} by User {self.user_id}>'

# Report model for content moderation


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    # Can be null if user is logged in
    email = db.Column(db.String(120), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey(
        'user.id'), nullable=True)  # Optional link to user
    # pending, reviewed, resolved
    status = db.Column(db.String(20), default='pending')
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='reports', lazy=True)

    def __repr__(self):
        return f'<Report {self.title}>'


class Follow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey(
        'user.id'), nullable=False, index=True)
    followed_id = db.Column(db.Integer, db.ForeignKey(
        'user.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint(
        'follower_id', 'followed_id', name='unique_follow'),)


class Bookmark(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey(
        'user.id'), nullable=False, index=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint(
        'user_id', 'post_id', name='unique_bookmark'),)


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # Recipient of the notification
    user_id = db.Column(db.Integer, db.ForeignKey(
        'user.id'), nullable=False, index=True)
    actor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    kind = db.Column(db.String(20), nullable=False)  # like, comment, follow, mention
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=True)
    comment_id = db.Column(db.Integer, db.ForeignKey(
        'comment.id'), nullable=True)
    is_read = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    actor = db.relationship('User', foreign_keys=[actor_id])
    post = db.relationship('Post')
    comment = db.relationship('Comment')


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey(
        'user.id'), nullable=False, index=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey(
        'user.id'), nullable=False, index=True)
    body = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    sender = db.relationship('User', foreign_keys=[sender_id])
    recipient = db.relationship('User', foreign_keys=[recipient_id])


# ---------------------------------------------------------------------------
# Schema upgrade for existing databases
# ---------------------------------------------------------------------------

# db.create_all() creates missing tables but never adds columns to tables that
# already exist, so older users.db files get the new columns added here.
SCHEMA_ADDITIONS = {
    'user': {
        'is_active': 'BOOLEAN NOT NULL DEFAULT 1',
        'username': 'VARCHAR(30)',
        'bio': 'VARCHAR(280)',
        'location': 'VARCHAR(100)',
        'website': 'VARCHAR(200)',
        'cover_picture': 'VARCHAR(200)',
        'created_at': 'DATETIME',
    },
    'post': {
        'image': 'VARCHAR(200)',
        'updated_at': 'DATETIME',
    },
}


def generate_username(seed):
    base = re.sub(r'[^a-z0-9_]', '', (seed or '').split('@')[0].lower())[:20]
    if len(base) < 3:
        base = (base + 'user')[:20]
    candidate, n = base, 1
    while candidate in RESERVED_USERNAMES or \
            User.query.filter(func.lower(User.username) == candidate).first():
        n += 1
        candidate = f'{base}{n}'
    return candidate


def sync_schema():
    inspector = inspect(db.engine)
    with db.engine.begin() as conn:
        for table, columns in SCHEMA_ADDITIONS.items():
            existing = {c['name'] for c in inspector.get_columns(table)}
            for name, ddl in columns.items():
                if name not in existing:
                    conn.execute(
                        text(f'ALTER TABLE "{table}" ADD COLUMN {name} {ddl}'))

    for user in User.query.filter(User.username.is_(None)).all():
        user.username = generate_username(user.email or user.first_name)
    db.session.commit()

    with db.engine.begin() as conn:
        conn.execute(text(
            'CREATE UNIQUE INDEX IF NOT EXISTS ix_user_username ON "user" (username)'))


with app.app_context():
    db.create_all()
    sync_schema()


# ---------------------------------------------------------------------------
# Request helpers: current user, CSRF, JSON detection, redirects
# ---------------------------------------------------------------------------

def wants_json():
    return request.headers.get('X-Requested-With') == 'XMLHttpRequest' or \
        request.accept_mimetypes.best == 'application/json'


def safe_path(target):
    """Return target only if it is a local path (prevents open redirects)."""
    if not target or not target.startswith('/') or target.startswith('//') or '\\' in target:
        return None
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc:
        return None
    return target


def back_url(default='newposts'):
    ref = request.referrer
    if ref:
        parsed = urlparse(ref)
        if parsed.netloc == request.host:
            path = parsed.path + (f'?{parsed.query}' if parsed.query else '')
            if safe_path(path):
                return path
    return url_for(default)


def csrf_token():
    token = session.get('_csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['_csrf_token'] = token
    return token


@app.before_request
def load_current_user():
    g.user = None
    if request.endpoint == 'static':
        return
    uid = session.get('user_id')
    if uid is not None:
        user = db.session.get(User, uid)
        if user is None or not user.is_active:
            session.pop('user_id', None)
        else:
            g.user = user


@app.before_request
def csrf_protect():
    if request.method not in ('POST', 'PUT', 'PATCH', 'DELETE') or \
            not app.config.get('CSRF_ENABLED', True):
        return
    sent = request.form.get('csrf_token') or request.headers.get('X-CSRFToken', '')
    expected = session.get('_csrf_token', '')
    if not expected or not hmac.compare_digest(sent, expected):
        message = 'Your session expired. Please refresh the page and try again.'
        if wants_json():
            return jsonify(error=message), 400
        flash(message, 'danger')
        return redirect(back_url('home'))


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
            if wants_json():
                return jsonify(error='Please sign in to continue.',
                               login_url=url_for('login')), 401
            flash('Please sign in to continue.', 'info')
            next_path = request.full_path.rstrip('?') if request.method == 'GET' \
                else urlparse(back_url('home')).path
            return redirect(url_for('login', next=next_path))
        return f(*args, **kwargs)
    return decorated_function


def json_or_redirect(payload, message=None, category='success', status=200, target=None):
    if wants_json():
        if message:
            payload.setdefault('message', message)
        return jsonify(payload), status
    if message:
        flash(message, category)
    return redirect(target or back_url())


# ---------------------------------------------------------------------------
# Uploads
# ---------------------------------------------------------------------------

class UploadError(ValueError):
    pass


IMAGE_SIGNATURES = (b'\x89PNG', b'\xff\xd8\xff', b'GIF87a', b'GIF89a', b'RIFF')


def save_upload(file_storage, folder_key):
    """Validate and store an uploaded image. Returns the stored filename or None."""
    if not file_storage or not file_storage.filename:
        return None
    if not allowed_file(file_storage.filename):
        raise UploadError('Please upload a PNG, JPG, GIF or WEBP image.')
    head = file_storage.stream.read(12)
    file_storage.stream.seek(0)
    if not head.startswith(IMAGE_SIGNATURES) or \
            (head.startswith(b'RIFF') and head[8:12] != b'WEBP'):
        raise UploadError("That file doesn't look like a valid image.")
    ext = file_storage.filename.rsplit('.', 1)[1].lower()
    filename = f"{int(datetime.utcnow().timestamp())}_{secrets.token_hex(4)}.{ext}"
    file_storage.save(os.path.join(app.config[folder_key], filename))
    return filename


def delete_upload(folder_key, filename):
    if not filename or filename == 'default.jpg':
        return
    path = os.path.join(app.config[folder_key], os.path.basename(filename))
    try:
        if os.path.isfile(path):
            os.remove(path)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Rich text, dates and other template helpers
# ---------------------------------------------------------------------------

TAG_PATTERN = r'(?<![\w#&])#(\w*[^\W\d_]\w*)'
MENTION_PATTERN = r'(?<![\w@])@([A-Za-z0-9_]{3,30})'
TAG_RE = re.compile(TAG_PATTERN)
MENTION_RE = re.compile(MENTION_PATTERN)
RICH_RE = re.compile(
    r'(?P<url>https?://[^\s<>"\']+)'
    r'|(?<![\w#&])#(?P<tag>\w*[^\W\d_]\w*)'
    r'|(?<![\w@])@(?P<mention>[A-Za-z0-9_]{3,30})')


def extract_tags(value):
    return [t.lower() for t in TAG_RE.findall(value or '') if len(t) <= 50]


def extract_mentions(value):
    return {m.lower() for m in MENTION_RE.findall(value or '')}


@app.template_filter('rich')
def render_rich(value):
    """Escape user text, then link URLs, #hashtags and @mentions."""
    if not value:
        return Markup('')
    value = value.replace('\r\n', '\n')
    out, pos = [], 0
    for m in RICH_RE.finditer(value):
        out.append(escape(value[pos:m.start()]))
        if m.group('url'):
            url, trail = m.group('url'), ''
            while url and url[-1] in '.,;:!?)]}\'"':
                trail, url = url[-1] + trail, url[:-1]
            label = url.split('://', 1)[1]
            if len(label) > 48:
                label = label[:45] + '…'
            out.append(Markup('<a href="{0}" class="rich-link" target="_blank" '
                              'rel="noopener nofollow ugc">{1}</a>').format(url, label))
            out.append(escape(trail))
        elif m.group('tag'):
            tag = m.group('tag')
            out.append(Markup('<a href="{0}" class="rich-tag">#{1}</a>').format(
                url_for('tag', name=tag.lower()), tag))
        else:
            name = m.group('mention')
            out.append(Markup('<a href="{0}" class="rich-mention">@{1}</a>').format(
                url_for('user_profile', username=name.lower()), name))
        pos = m.end()
    out.append(escape(value[pos:]))
    return Markup('').join(out).replace('\n', Markup('<br>'))


@app.template_filter('nl2br')
def nl2br_filter(s):
    if s is None:
        return ""
    return s.replace('\n', '<br>')


@app.template_filter('timeago')
def timeago_filter(dt):
    if not dt:
        return ''
    now = datetime.utcnow()
    seconds = (now - dt).total_seconds()
    if seconds < 60:
        return 'just now'
    if seconds < 3600:
        return f'{int(seconds // 60)}m'
    if seconds < 86400:
        return f'{int(seconds // 3600)}h'
    if seconds < 7 * 86400:
        return f'{int(seconds // 86400)}d'
    if dt.year == now.year:
        return f"{dt.strftime('%b')} {dt.day}"
    return f"{dt.strftime('%b')} {dt.day}, {dt.year}"


@app.template_filter('isodate')
def isodate_filter(dt):
    return dt.replace(microsecond=0).isoformat() + 'Z' if dt else ''


@app.template_filter('fulldate')
def fulldate_filter(dt):
    return f"{dt.strftime('%B')} {dt.day}, {dt.year} · {dt.strftime('%H:%M')} UTC" if dt else ''


@app.template_filter('compact')
def compact_number(n):
    n = n or 0
    if n < 1000:
        return str(n)
    if n < 1_000_000:
        return f'{n / 1000:.1f}'.rstrip('0').rstrip('.') + 'K'
    return f'{n / 1_000_000:.1f}'.rstrip('0').rstrip('.') + 'M'


@app.template_filter('highlight')
def highlight_filter(value, query):
    value = value or ''
    if not query:
        return escape(value)
    pattern = re.compile(re.escape(query), re.IGNORECASE)
    out, pos = [], 0
    for m in pattern.finditer(value):
        out.append(escape(value[pos:m.start()]))
        out.append(Markup('<mark>{0}</mark>').format(m.group(0)))
        pos = m.end()
    out.append(escape(value[pos:]))
    return Markup('').join(out)


_asset_versions = {}


def asset(path):
    """Static URL with a cache-busting version based on the file's mtime."""
    version = _asset_versions.get(path)
    if version is None or app.debug:
        try:
            version = int(os.path.getmtime(os.path.join(app.static_folder, path)))
        except OSError:
            version = 0
        _asset_versions[path] = version
    return url_for('static', filename=path, v=version)


def following_ids():
    if 'following_ids' not in g:
        g.following_ids = set()
        if g.get('user'):
            g.following_ids = {fid for (fid,) in db.session.query(Follow.followed_id)
                               .filter(Follow.follower_id == g.user.id)}
    return g.following_ids


def is_following(user_id):
    return user_id in following_ids()


def unread_counts():
    if 'unread_counts' not in g:
        counts = {'notifications': 0, 'messages': 0}
        if g.get('user'):
            counts['notifications'] = Notification.query.filter_by(
                user_id=g.user.id, is_read=False).count()
            counts['messages'] = Message.query.filter_by(
                recipient_id=g.user.id, is_read=False).count()
        g.unread_counts = counts
    return g.unread_counts


_trending_cache = {'at': 0, 'data': []}


def trending_tags(limit=6):
    if time.time() - _trending_cache['at'] > 60 or app.debug or app.testing:
        rows = db.session.query(Post.title, Post.content).order_by(
            Post.id.desc()).limit(500).all()
        counter = Counter()
        for title, content in rows:
            counter.update(set(extract_tags(f'{title} {content}')))
        _trending_cache.update(at=time.time(), data=counter.most_common(20))
    return _trending_cache['data'][:limit]


def follower_counts_subquery():
    return db.session.query(
        Follow.followed_id.label('uid'), func.count(Follow.id).label('n')
    ).group_by(Follow.followed_id).subquery()


def who_to_follow(limit=3):
    if not g.get('user'):
        return []
    exclude = following_ids() | {g.user.id}
    fc = follower_counts_subquery()
    return (User.query.outerjoin(fc, fc.c.uid == User.id)
            .filter(~User.id.in_(exclude), User.is_active.is_(True))
            .order_by(func.coalesce(fc.c.n, 0).desc(), User.id.desc())
            .limit(limit).all())


def user_stats(user):
    posts = Post.query.filter_by(user_id=user.id).count()
    followers = Follow.query.filter_by(followed_id=user.id).count()
    following = Follow.query.filter_by(follower_id=user.id).count()
    likes = db.session.query(func.count(Reaction.id)).join(Post, Reaction.post_id == Post.id) \
        .filter(Post.user_id == user.id, Reaction.reaction_type == 'like').scalar() or 0
    return {'posts': posts, 'followers': followers, 'following': following, 'likes': likes}


def onboarding_steps():
    user = g.user
    stats = user_stats(user)
    steps = [
        {'done': bool(user.avatar_url), 'label': 'Add a profile photo',
         'url': url_for('settings') + '#profile', 'icon': 'camera'},
        {'done': bool(user.bio), 'label': 'Write a short bio',
         'url': url_for('settings') + '#profile', 'icon': 'edit'},
        {'done': stats['following'] >= 3, 'label': 'Follow 3 people',
         'url': url_for('people'), 'icon': 'users'},
        {'done': stats['posts'] > 0, 'label': 'Share your first post',
         'url': url_for('create_post'), 'icon': 'feather'},
    ]
    done = sum(1 for s in steps if s['done'])
    return {'steps': steps, 'done': done, 'total': len(steps),
            'complete': done == len(steps)}


app.jinja_env.globals.update(
    asset=asset, csrf_token=csrf_token, is_following=is_following,
    unread_counts=unread_counts, trending_tags=trending_tags,
    who_to_follow=who_to_follow, MAX_POST_LENGTH=MAX_POST_LENGTH,
    MAX_TITLE_LENGTH=MAX_TITLE_LENGTH, MAX_COMMENT_LENGTH=MAX_COMMENT_LENGTH,
    MAX_BIO_LENGTH=MAX_BIO_LENGTH, MAX_MESSAGE_LENGTH=MAX_MESSAGE_LENGTH)


@app.context_processor
def inject_user():
    return dict(current_user=g.get('user'))


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

def base_post_query():
    return Post.query.join(Post.user).options(contains_eager(Post.user))


def paginate(query, page, per_page=None):
    per_page = per_page or app.config['POSTS_PER_PAGE']
    items = query.offset((page - 1) * per_page).limit(per_page + 1).all()
    return items[:per_page], len(items) > per_page


def reaction_counts(post_ids):
    counts = defaultdict(int)
    if post_ids:
        rows = db.session.query(Reaction.post_id, Reaction.reaction_type, func.count(Reaction.id)) \
            .filter(Reaction.post_id.in_(post_ids)) \
            .group_by(Reaction.post_id, Reaction.reaction_type)
        for post_id, kind, n in rows:
            counts[(post_id, kind)] = n
    return counts


def hydrate(posts):
    """Attach reaction counts, the viewer's state and comments to posts in a few queries."""
    ids = [p.id for p in posts]
    if not ids:
        return posts
    counts = reaction_counts(ids)
    comments = defaultdict(list)
    for c in (Comment.query.join(Comment.user).options(contains_eager(Comment.user))
              .filter(Comment.post_id.in_(ids))
              .order_by(Comment.date_created.asc(), Comment.id.asc())):
        comments[c.post_id].append(c)
    mine, saved = {}, set()
    if g.get('user'):
        mine = dict(db.session.query(Reaction.post_id, Reaction.reaction_type)
                    .filter(Reaction.user_id == g.user.id, Reaction.post_id.in_(ids)).all())
        saved = {pid for (pid,) in db.session.query(Bookmark.post_id)
                 .filter(Bookmark.user_id == g.user.id, Bookmark.post_id.in_(ids))}
    for p in posts:
        p.like_count = counts[(p.id, 'like')]
        p.dislike_count = counts[(p.id, 'dislike')]
        p.my_reaction = mine.get(p.id)
        p.is_bookmarked = p.id in saved
        p.comment_list = comments[p.id]
        p.comment_count = len(p.comment_list)
    return posts


def popular_posts(page):
    per_page = app.config['POSTS_PER_PAGE']
    candidates = base_post_query().order_by(Post.date_posted.desc()).limit(300).all()
    ids = [p.id for p in candidates]
    counts = reaction_counts(ids)
    comment_counts = dict(db.session.query(Comment.post_id, func.count(Comment.id))
                          .filter(Comment.post_id.in_(ids)).group_by(Comment.post_id).all()) if ids else {}
    now = datetime.utcnow()

    def score(p):
        engagement = counts[(p.id, 'like')] * 2 + comment_counts.get(p.id, 0) * 3 \
            - counts[(p.id, 'dislike')]
        age_hours = (now - (p.date_posted or now)).total_seconds() / 3600
        return (engagement / ((age_hours + 2) ** 0.8), p.id)

    ranked = sorted(candidates, key=score, reverse=True)
    start = (page - 1) * per_page
    return ranked[start:start + per_page], len(ranked) > start + per_page


def posts_fragment(posts, next_url):
    return jsonify(html=render_template('partials/posts.html', posts=posts), next=next_url)


def get_user_or_404(username):
    return User.query.filter(func.lower(User.username) == username.lower()).first_or_404()


def like_escape(value):
    return value.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')


def posts_with_tag(tag):
    tag = tag.lower()
    candidates = base_post_query().filter(or_(
        Post.content.ilike(f'%#{like_escape(tag)}%', escape='\\'),
        Post.title.ilike(f'%#{like_escape(tag)}%', escape='\\'))) \
        .order_by(Post.date_posted.desc(), Post.id.desc()).all()
    return [p for p in candidates if tag in extract_tags(f'{p.title} {p.content}')]


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------

def notify(recipient_id, kind, post_id=None, comment_id=None):
    if not g.get('user') or recipient_id == g.user.id:
        return
    db.session.add(Notification(user_id=recipient_id, actor_id=g.user.id, kind=kind,
                                post_id=post_id, comment_id=comment_id))


def notify_mentions(value, post_id=None, comment_id=None, skip=()):
    names = extract_mentions(value)
    if not names:
        return
    for user in User.query.filter(func.lower(User.username).in_(names)):
        if user.id not in skip:
            notify(user.id, 'mention', post_id=post_id, comment_id=comment_id)


def clear_notifications(**filters):
    Notification.query.filter_by(**filters).delete(synchronize_session=False)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_post(title, content):
    errors = []
    if not title:
        errors.append('Please give your post a title.')
    elif len(title) > MAX_TITLE_LENGTH:
        errors.append(f'Titles can be at most {MAX_TITLE_LENGTH} characters.')
    if not content:
        errors.append("Your post can't be empty.")
    elif len(content) > MAX_POST_LENGTH:
        errors.append(f'Posts can be at most {MAX_POST_LENGTH} characters.')
    return errors


def validate_username(username, current_user_id=None):
    if not USERNAME_RE.match(username or ''):
        return 'Usernames are 3–30 characters: letters, numbers and underscores.'
    if username in RESERVED_USERNAMES:
        return 'That username is reserved.'
    existing = User.query.filter(func.lower(User.username) == username).first()
    if existing and existing.id != current_user_id:
        return 'That username is already taken.'
    return None


def normalize_website(url):
    url = (url or '').strip()
    if url and not re.match(r'^https?://', url, re.IGNORECASE):
        url = 'https://' + url
    return url[:200]


# ---------------------------------------------------------------------------
# Landing, auth
# ---------------------------------------------------------------------------

@app.route('/')
def home():
    if g.user:
        return redirect(url_for('newposts'))
    stats = {
        'users': User.query.count(),
        'posts': Post.query.count(),
        'comments': Comment.query.count(),
        'reactions': Reaction.query.count(),
    }
    preview = hydrate(base_post_query().order_by(
        Post.date_posted.desc()).limit(2).all())
    return render_template('home.html', stats=stats, preview=preview)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if g.user:
        return redirect(url_for('newposts'))
    form = {}
    if request.method == 'POST':
        form = {k: (request.form.get(k) or '').strip()
                for k in ('first_name', 'last_name', 'username', 'email', 'gender')}
        form['username'] = form['username'].lower().lstrip('@')
        form['email'] = form['email'].lower()
        password = request.form.get('password') or ''
        errors = {}

        if not form['first_name']:
            errors['first_name'] = 'Please enter your first name.'
        if not form['last_name']:
            errors['last_name'] = 'Please enter your last name.'
        if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', form['email']):
            errors['email'] = 'Please enter a valid email address.'
        elif User.query.filter(or_(func.lower(User.email) == form['email'],
                                   User.user_id == form['email'])).first():
            errors['email'] = 'An account with this email already exists.'
        username_error = validate_username(form['username'])
        if username_error:
            errors['username'] = username_error
        if len(password) < 6:
            errors['password'] = 'Use at least 6 characters.'
        if form['gender'] not in ('male', 'female', 'other'):
            errors['gender'] = 'Please choose an option.'

        # Handle profile picture upload
        profile_pic_filename = 'default.jpg'  # Default image
        if not errors:
            try:
                profile_pic_filename = save_upload(
                    request.files.get('profile_picture'), 'UPLOAD_FOLDER') or 'default.jpg'
            except UploadError as e:
                errors['profile_picture'] = str(e)

        if errors:
            flash('Please fix the highlighted fields.', 'danger')
            return render_template('signup.html', form=form, errors=errors), 400

        new_user = User(
            first_name=form['first_name'],
            last_name=form['last_name'],
            user_id=form['email'],
            email=form['email'],
            username=form['username'],
            password=generate_password_hash(password),
            gender=form['gender'],
            profile_picture=profile_pic_filename,
            created_at=datetime.utcnow()
        )
        db.session.add(new_user)
        db.session.commit()

        session['user_id'] = new_user.id
        flash(f"Welcome to Postfy, {new_user.first_name}! 🎉", 'success')
        return redirect(url_for('newposts'))

    return render_template('signup.html', form=form, errors={})


@app.route('/login', methods=['GET', 'POST'])
def login():
    next_path = safe_path(request.values.get('next'))
    if g.user:
        return redirect(next_path or url_for('newposts'))
    email = ''
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip()
        password = request.form.get('password') or ''

        user = User.query.filter(or_(func.lower(User.email) == email.lower(),
                                     func.lower(User.username) == email.lower().lstrip('@'))).first()

        if user and check_password_hash(user.password, password):
            if not user.is_active:
                flash('This account has been deactivated.', 'danger')
            else:
                session['user_id'] = user.id
                session.permanent = bool(request.form.get('remember'))
                flash(f"Welcome back, {user.first_name}! 👋", 'success')
                return redirect(next_path or url_for('newposts'))
        else:
            flash("That email and password don't match. Please try again.", 'danger')

    return render_template('login.html', email=email, next=next_path)


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("You have been logged out", 'info')
    return redirect(url_for('login'))


# ---------------------------------------------------------------------------
# Feed & posts
# ---------------------------------------------------------------------------

@app.route('/newposts')
@app.route('/feed')
@login_required
def newposts():
    tab = request.args.get('tab', 'latest')
    if tab not in ('latest', 'following', 'popular'):
        tab = 'latest'
    page = max(request.args.get('page', 1, type=int), 1)

    if tab == 'popular':
        posts, has_next = popular_posts(page)
    else:
        query = base_post_query()
        if tab == 'following':
            query = query.filter(Post.user_id.in_(following_ids() | {g.user.id}))
        posts, has_next = paginate(
            query.order_by(Post.date_posted.desc(), Post.id.desc()), page)
    hydrate(posts)
    next_url = url_for('newposts', tab=tab, page=page + 1) if has_next else None

    if wants_json():
        return posts_fragment(posts, next_url)
    latest_id = db.session.query(func.max(Post.id)).scalar() or 0
    return render_template('newpost.html', posts=posts, tab=tab, next_url=next_url,
                           latest_id=latest_id, onboarding=onboarding_steps())


@app.route('/post/<int:post_id>')
def post_detail(post_id):
    post = base_post_query().filter(Post.id == post_id).first_or_404()
    hydrate([post])
    more_posts = base_post_query().filter(Post.user_id == post.user_id, Post.id != post.id) \
        .order_by(Post.date_posted.desc()).limit(3).all()
    return render_template('post_detail.html', post=post, more_posts=more_posts,
                           author_stats=user_stats(post.user))


@app.route('/create_post', methods=['GET', 'POST'])
@login_required
def create_post():
    if request.method == 'POST':
        post_title = (request.form.get('post_title') or '').strip()
        post_content = (request.form.get('post_content') or '').strip()
        errors = validate_post(post_title, post_content)
        image = None
        if not errors:
            try:
                image = save_upload(request.files.get('post_image'), 'POST_IMAGE_FOLDER')
            except UploadError as e:
                errors.append(str(e))
        if errors:
            if wants_json():
                return jsonify(error=errors[0]), 400
            for error in errors:
                flash(error, 'danger')
            return render_template('create_post.html',
                                   form={'title': post_title, 'content': post_content}), 400

        new_post = Post(
            title=post_title,
            content=post_content,
            user_id=g.user.id,
            date_posted=datetime.utcnow(),
            image=image
        )
        db.session.add(new_post)
        db.session.flush()
        notify_mentions(f'{post_title} {post_content}', post_id=new_post.id)
        db.session.commit()

        if wants_json():
            hydrate([new_post])
            return jsonify(ok=True, message='Your post is live! 🎉',
                           html=render_template('partials/posts.html', posts=[new_post]),
                           url=url_for('post_detail', post_id=new_post.id))
        flash("Your post is live! 🎉", 'success')
        return redirect(url_for('newposts'))

    return render_template('create_post.html', form={})


@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)

    if post.user_id != g.user.id:
        flash("You can only edit your own posts!", 'danger')
        return redirect(url_for('newposts'))

    if request.method == 'POST':
        post_title = (request.form.get('post_title') or '').strip()
        post_content = (request.form.get('post_content') or '').strip()
        errors = validate_post(post_title, post_content)
        new_image = None
        if not errors:
            try:
                new_image = save_upload(request.files.get('post_image'), 'POST_IMAGE_FOLDER')
            except UploadError as e:
                errors.append(str(e))
        if errors:
            for error in errors:
                flash(error, 'danger')
            post.title, post.content = post_title, post_content
            db.session.rollback()
            return render_template('edit_post.html', post=post,
                                   form={'title': post_title, 'content': post_content}), 400

        post.title = post_title
        post.content = post_content
        if new_image or request.form.get('remove_image'):
            delete_upload('POST_IMAGE_FOLDER', post.image)
            post.image = new_image
        post.updated_at = datetime.utcnow()

        db.session.commit()
        flash("Post updated successfully!", 'success')
        return redirect(url_for('post_detail', post_id=post.id))

    return render_template('edit_post.html', post=post,
                           form={'title': post.title, 'content': post.content})


def purge_post(post):
    Reaction.query.filter_by(post_id=post.id).delete(synchronize_session=False)
    comment_ids = [cid for (cid,) in db.session.query(Comment.id).filter_by(post_id=post.id)]
    if comment_ids:
        Notification.query.filter(Notification.comment_id.in_(comment_ids)) \
            .delete(synchronize_session=False)
    Comment.query.filter_by(post_id=post.id).delete(synchronize_session=False)
    Bookmark.query.filter_by(post_id=post.id).delete(synchronize_session=False)
    clear_notifications(post_id=post.id)
    delete_upload('POST_IMAGE_FOLDER', post.image)
    db.session.delete(post)


@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)

    if post.user_id != g.user.id:
        return json_or_redirect({'error': 'You can only delete your own posts!'},
                                "You can only delete your own posts!", 'danger', 403)

    purge_post(post)
    db.session.commit()

    target = back_url()
    if f'/post/{post_id}' in target or f'/edit_post/{post_id}' in target:
        target = url_for('newposts')
    return json_or_redirect({'ok': True}, "Post deleted successfully!", target=target)


# ---------------------------------------------------------------------------
# Comments & reactions
# ---------------------------------------------------------------------------

@app.route('/add_comment/<int:post_id>', methods=['POST'])
@login_required
def add_comment(post_id):
    post = Post.query.get_or_404(post_id)
    comment_content = (request.form.get('comment_content') or '').strip()

    if not comment_content:
        return json_or_redirect({'error': 'Comment cannot be empty!'},
                                "Comment cannot be empty!", 'danger', 400)
    if len(comment_content) > MAX_COMMENT_LENGTH:
        message = f'Comments can be at most {MAX_COMMENT_LENGTH} characters.'
        return json_or_redirect({'error': message}, message, 'danger', 400)

    new_comment = Comment(
        content=comment_content,
        post_id=post_id,
        user_id=g.user.id,
        date_created=datetime.utcnow()
    )

    db.session.add(new_comment)
    db.session.flush()
    notify(post.user_id, 'comment', post_id=post.id, comment_id=new_comment.id)
    notify_mentions(comment_content, post_id=post.id, comment_id=new_comment.id,
                    skip={post.user_id})
    db.session.commit()

    if wants_json():
        return jsonify(ok=True, count=Comment.query.filter_by(post_id=post_id).count(),
                       html=render_template('partials/comment.html', comment=new_comment,
                                            post=post))
    flash("Comment added successfully!", 'success')
    return redirect(back_url() + f'#comment-{new_comment.id}')


@app.route('/edit_comment/<int:comment_id>', methods=['GET', 'POST'])
@login_required
def edit_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)

    # Check if the current user is the author of the comment
    if comment.user_id != g.user.id:
        return json_or_redirect({'error': 'You can only edit your own comments!'},
                                "You can only edit your own comments!", 'danger', 403,
                                target=url_for('newposts'))

    if request.method == 'POST':
        comment_content = (request.form.get('comment_content') or '').strip()

        if not comment_content or len(comment_content) > MAX_COMMENT_LENGTH:
            message = "Comment cannot be empty!" if not comment_content else \
                f'Comments can be at most {MAX_COMMENT_LENGTH} characters.'
            if wants_json():
                return jsonify(error=message), 400
            flash(message, 'danger')
            return redirect(url_for('edit_comment', comment_id=comment_id))

        comment.content = comment_content
        db.session.commit()

        if wants_json():
            return jsonify(ok=True, html=render_template('partials/comment.html', comment=comment,
                                                         post=comment.post))
        flash("Comment updated successfully!", 'success')
        return redirect(url_for('post_detail', post_id=comment.post_id) + f'#comment-{comment.id}')

    # Get post information for context
    post = db.session.get(Post, comment.post_id)

    return render_template('edit_comment.html', comment=comment, post=post)


@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    post_id = comment.post_id

    # Comment authors and the owner of the post can remove a comment
    if comment.user_id != g.user.id and comment.post.user_id != g.user.id:
        return json_or_redirect({'error': 'You can only delete your own comments!'},
                                "You can only delete your own comments!", 'danger', 403)

    clear_notifications(comment_id=comment.id)
    db.session.delete(comment)
    db.session.commit()

    return json_or_redirect({'ok': True, 'count': Comment.query.filter_by(post_id=post_id).count()},
                            "Comment deleted successfully!")


@app.route('/react/<string:reaction_type>/<int:post_id>', methods=['POST'])
@login_required
def react_to_post(reaction_type, post_id):
    if reaction_type not in ['like', 'dislike']:
        return json_or_redirect({'error': 'Invalid reaction type!'}, 'Invalid reaction type!',
                                'danger', 400)

    # Check if post exists
    post = Post.query.get_or_404(post_id)
    user_id = g.user.id

    # Check if user already reacted to this post
    existing_reaction = Reaction.query.filter_by(
        post_id=post_id,
        user_id=user_id
    ).first()

    current = None
    if existing_reaction:
        if existing_reaction.reaction_type == reaction_type:
            # If the same reaction already exists, remove it (toggle off)
            db.session.delete(existing_reaction)
        else:
            # If different reaction, update it
            existing_reaction.reaction_type = reaction_type
            current = reaction_type
    else:
        # Create new reaction
        db.session.add(Reaction(
            post_id=post_id,
            user_id=user_id,
            reaction_type=reaction_type
        ))
        current = reaction_type

    clear_notifications(user_id=post.user_id, actor_id=user_id, post_id=post.id, kind='like')
    if current == 'like':
        notify(post.user_id, 'like', post_id=post.id)
    db.session.commit()

    counts = reaction_counts([post.id])
    return json_or_redirect({'ok': True, 'reaction': current,
                             'like_count': counts[(post.id, 'like')],
                             'dislike_count': counts[(post.id, 'dislike')]})


@app.route('/bookmark/<int:post_id>', methods=['POST'])
@login_required
def toggle_bookmark(post_id):
    Post.query.get_or_404(post_id)
    existing = Bookmark.query.filter_by(user_id=g.user.id, post_id=post_id).first()
    if existing:
        db.session.delete(existing)
        message = 'Removed from bookmarks'
    else:
        db.session.add(Bookmark(user_id=g.user.id, post_id=post_id))
        message = 'Saved to bookmarks'
    db.session.commit()
    return json_or_redirect({'ok': True, 'bookmarked': not existing}, message)


@app.route('/bookmarks')
@login_required
def bookmarks():
    page = max(request.args.get('page', 1, type=int), 1)
    query = base_post_query().join(Bookmark, Bookmark.post_id == Post.id) \
        .filter(Bookmark.user_id == g.user.id).order_by(Bookmark.created_at.desc())
    posts, has_next = paginate(query, page)
    hydrate(posts)
    next_url = url_for('bookmarks', page=page + 1) if has_next else None
    if wants_json():
        return posts_fragment(posts, next_url)
    return render_template('bookmarks.html', posts=posts, next_url=next_url)


# ---------------------------------------------------------------------------
# People, profiles & follows
# ---------------------------------------------------------------------------

@app.route('/profile')
@login_required
def profile():
    return redirect(url_for('user_profile', username=g.user.handle))


@app.route('/u/<username>')
def user_profile(username):
    user = get_user_or_404(username)
    tab = request.args.get('tab', 'posts')
    if tab not in ('posts', 'media', 'likes'):
        tab = 'posts'
    page = max(request.args.get('page', 1, type=int), 1)

    query = base_post_query()
    if tab == 'likes':
        query = query.join(Reaction, Reaction.post_id == Post.id) \
            .filter(Reaction.user_id == user.id, Reaction.reaction_type == 'like') \
            .order_by(Reaction.created_at.desc())
    else:
        query = query.filter(Post.user_id == user.id)
        if tab == 'media':
            query = query.filter(Post.image.isnot(None))
        query = query.order_by(Post.date_posted.desc(), Post.id.desc())
    posts, has_next = paginate(query, page)
    hydrate(posts)
    next_url = url_for('user_profile', username=user.handle, tab=tab, page=page + 1) \
        if has_next else None
    if wants_json():
        return posts_fragment(posts, next_url)

    follows_you = bool(g.user and Follow.query.filter_by(
        follower_id=user.id, followed_id=g.user.id).first())
    return render_template('profile.html', user=user, posts=posts, tab=tab,
                           next_url=next_url, stats=user_stats(user), follows_you=follows_you)


@app.route('/u/<username>/<any(followers, following):kind>')
def follow_list(username, kind):
    user = get_user_or_404(username)
    if kind == 'followers':
        query = User.query.join(Follow, Follow.follower_id == User.id) \
            .filter(Follow.followed_id == user.id)
    else:
        query = User.query.join(Follow, Follow.followed_id == User.id) \
            .filter(Follow.follower_id == user.id)
    users = query.order_by(Follow.created_at.desc()).all()
    return render_template('follow_list.html', user=user, users=users, kind=kind,
                           stats=user_stats(user))


@app.route('/follow/<int:user_id>', methods=['POST'])
@login_required
def toggle_follow(user_id):
    target = db.session.get(User, user_id) or abort(404)
    if target.id == g.user.id:
        return json_or_redirect({'error': "You can't follow yourself."},
                                "You can't follow yourself.", 'danger', 400)
    existing = Follow.query.filter_by(follower_id=g.user.id, followed_id=target.id).first()
    if existing:
        db.session.delete(existing)
        clear_notifications(user_id=target.id, actor_id=g.user.id, kind='follow')
        message = f'Unfollowed {target.first_name}'
    else:
        db.session.add(Follow(follower_id=g.user.id, followed_id=target.id))
        notify(target.id, 'follow')
        message = f'You are now following {target.first_name}'
    db.session.commit()
    followers = Follow.query.filter_by(followed_id=target.id).count()
    return json_or_redirect({'ok': True, 'following': not existing, 'followers': followers},
                            message)


@app.route('/people')
@login_required
def people():
    q = (request.args.get('q') or '').strip()
    fc = follower_counts_subquery()
    query = User.query.outerjoin(fc, fc.c.uid == User.id) \
        .filter(User.id != g.user.id, User.is_active.is_(True))
    if q:
        like = f'%{like_escape(q.lstrip("@"))}%'
        query = query.filter(or_(
            User.first_name.ilike(like, escape='\\'), User.last_name.ilike(like, escape='\\'),
            User.username.ilike(like, escape='\\'),
            (User.first_name + ' ' + User.last_name).ilike(like, escape='\\')))
    users = query.order_by(func.coalesce(fc.c.n, 0).desc(), User.id.desc()).limit(60).all()
    counts = dict(db.session.query(fc.c.uid, fc.c.n).all())
    return render_template('people.html', users=users, q=q, follower_counts=counts)


# ---------------------------------------------------------------------------
# Search & tags
# ---------------------------------------------------------------------------

def search_users(q, limit):
    like = f'%{like_escape(q.lstrip("@"))}%'
    return User.query.filter(User.is_active.is_(True), or_(
        User.first_name.ilike(like, escape='\\'), User.last_name.ilike(like, escape='\\'),
        User.username.ilike(like, escape='\\'),
        (User.first_name + ' ' + User.last_name).ilike(like, escape='\\'))).limit(limit).all()


def search_tags(q, limit=8):
    needle = q.lstrip('#').lower()
    return [(tag, n) for tag, n in trending_tags(20) if needle in tag][:limit]


@app.route('/search')
def search():
    q = (request.args.get('q') or '').strip()
    kind = request.args.get('type', 'top')
    if kind not in ('top', 'posts', 'people', 'tags'):
        kind = 'top'
    if q.startswith('#') and len(q) > 1 and ' ' not in q and kind == 'top':
        return redirect(url_for('tag', name=q[1:].lower()))

    users, posts, tags = [], [], []
    if q:
        if kind in ('top', 'people'):
            users = search_users(q, 5 if kind == 'top' else 40)
        if kind in ('top', 'posts'):
            like = f'%{like_escape(q)}%'
            posts = base_post_query().filter(or_(
                Post.title.ilike(like, escape='\\'), Post.content.ilike(like, escape='\\'))) \
                .order_by(Post.date_posted.desc()).limit(10 if kind == 'top' else 40).all()
            hydrate(posts)
        if kind in ('top', 'tags'):
            tags = search_tags(q)
    return render_template('search.html', q=q, kind=kind, users=users, posts=posts, tags=tags)


@app.route('/tag/<name>')
def tag(name):
    name = name.lower().lstrip('#')
    page = max(request.args.get('page', 1, type=int), 1)
    per_page = app.config['POSTS_PER_PAGE']
    matches = posts_with_tag(name)
    posts = matches[(page - 1) * per_page: page * per_page]
    hydrate(posts)
    next_url = url_for('tag', name=name, page=page + 1) if len(matches) > page * per_page else None
    if wants_json():
        return posts_fragment(posts, next_url)
    return render_template('tag.html', tag=name, posts=posts, total=len(matches),
                           next_url=next_url)


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------

@app.route('/notifications')
@login_required
def notifications():
    items = (Notification.query.join(Notification.actor).options(
        contains_eager(Notification.actor), joinedload(Notification.post),
        joinedload(Notification.comment))
        .filter(Notification.user_id == g.user.id)
        .order_by(Notification.created_at.desc()).limit(100).all())
    unread = [n for n in items if not n.is_read]
    earlier = [n for n in items if n.is_read]
    response = render_template('notifications.html', unread=unread, earlier=earlier)
    if unread:
        Notification.query.filter_by(user_id=g.user.id, is_read=False) \
            .update({'is_read': True}, synchronize_session=False)
        db.session.commit()
    return response


@app.route('/notifications/read', methods=['POST'])
@login_required
def mark_notifications_read():
    Notification.query.filter_by(user_id=g.user.id, is_read=False) \
        .update({'is_read': True}, synchronize_session=False)
    db.session.commit()
    return json_or_redirect({'ok': True}, 'All caught up!')


# ---------------------------------------------------------------------------
# Direct messages
# ---------------------------------------------------------------------------

def conversation_list():
    me = g.user.id
    rows = (Message.query.filter(or_(Message.sender_id == me, Message.recipient_id == me))
            .order_by(Message.created_at.desc(), Message.id.desc()).limit(1000).all())
    conversations, seen = [], {}
    for m in rows:
        other_id = m.recipient_id if m.sender_id == me else m.sender_id
        if other_id not in seen:
            seen[other_id] = {'last': m, 'unread': 0}
            conversations.append(other_id)
        if m.recipient_id == me and not m.is_read:
            seen[other_id]['unread'] += 1
    users = {u.id: u for u in User.query.filter(User.id.in_(conversations))} if conversations else {}
    return [dict(user=users[uid], **seen[uid]) for uid in conversations if uid in users]


def thread_messages(partner, after=0):
    me = g.user.id
    return (Message.query.filter(
        or_((Message.sender_id == me) & (Message.recipient_id == partner.id),
            (Message.sender_id == partner.id) & (Message.recipient_id == me)),
        Message.id > after)
        .order_by(Message.created_at.asc(), Message.id.asc()).all())


def mark_thread_read(partner):
    updated = Message.query.filter_by(sender_id=partner.id, recipient_id=g.user.id, is_read=False) \
        .update({'is_read': True}, synchronize_session=False)
    if updated:
        db.session.commit()


@app.route('/messages')
@login_required
def messages():
    return render_template('messages.html', conversations=conversation_list(),
                           partner=None, thread=[])


@app.route('/messages/<username>', methods=['GET', 'POST'])
@login_required
def conversation(username):
    partner = get_user_or_404(username)
    if partner.id == g.user.id:
        flash("You can't message yourself.", 'info')
        return redirect(url_for('messages'))

    if request.method == 'POST':
        body = (request.form.get('body') or '').strip()
        if not body or len(body) > MAX_MESSAGE_LENGTH:
            message = "Message can't be empty." if not body else \
                f'Messages can be at most {MAX_MESSAGE_LENGTH} characters.'
            return json_or_redirect({'error': message}, message, 'danger', 400,
                                    target=url_for('conversation', username=partner.handle))
        msg = Message(sender_id=g.user.id, recipient_id=partner.id, body=body)
        db.session.add(msg)
        db.session.commit()
        if wants_json():
            return jsonify(ok=True, id=msg.id,
                           html=render_template('partials/message.html', m=msg, partner=partner))
        return redirect(url_for('conversation', username=partner.handle))

    thread = thread_messages(partner)
    mark_thread_read(partner)
    return render_template('messages.html', conversations=conversation_list(),
                           partner=partner, thread=thread)


@app.route('/api/messages/<username>')
@login_required
def api_conversation(username):
    partner = get_user_or_404(username)
    after = request.args.get('after', 0, type=int)
    new = [m for m in thread_messages(partner, after) if m.sender_id == partner.id]
    mark_thread_read(partner)
    html = ''.join(render_template('partials/message.html', m=m, partner=partner) for m in new)
    last_seen = Message.query.filter_by(sender_id=g.user.id, recipient_id=partner.id, is_read=True) \
        .order_by(Message.id.desc()).first()
    return jsonify(html=html, last_id=new[-1].id if new else after,
                   seen_id=last_seen.id if last_seen else 0)


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html', stats=user_stats(g.user))


@app.route('/settings/profile', methods=['POST'])
@login_required
def settings_profile():
    user = g.user
    first_name = (request.form.get('first_name') or '').strip()
    last_name = (request.form.get('last_name') or '').strip()
    username = (request.form.get('username') or '').strip().lower().lstrip('@')
    bio = (request.form.get('bio') or '').strip()

    error = None
    if not first_name or not last_name:
        error = 'Please enter your first and last name.'
    elif len(bio) > MAX_BIO_LENGTH:
        error = f'Bios can be at most {MAX_BIO_LENGTH} characters.'
    else:
        error = validate_username(username, user.id)
    if error:
        flash(error, 'danger')
        return redirect(url_for('settings') + '#profile')

    try:
        avatar = save_upload(request.files.get('profile_picture'), 'UPLOAD_FOLDER')
        cover = save_upload(request.files.get('cover_picture'), 'COVER_FOLDER')
    except UploadError as e:
        flash(str(e), 'danger')
        return redirect(url_for('settings') + '#profile')

    if avatar or request.form.get('remove_avatar'):
        delete_upload('UPLOAD_FOLDER', user.profile_picture)
        user.profile_picture = avatar or 'default.jpg'
    if cover or request.form.get('remove_cover'):
        delete_upload('COVER_FOLDER', user.cover_picture)
        user.cover_picture = cover

    user.first_name, user.last_name, user.username = first_name, last_name, username
    user.bio = bio or None
    user.location = (request.form.get('location') or '').strip()[:100] or None
    user.website = normalize_website(request.form.get('website')) or None
    db.session.commit()
    flash('Profile updated ✨', 'success')
    return redirect(url_for('settings') + '#profile')


@app.route('/settings/account', methods=['POST'])
@login_required
def settings_account():
    user = g.user
    email = (request.form.get('email') or '').strip().lower()
    gender = request.form.get('gender') or user.gender
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        flash('Please enter a valid email address.', 'danger')
    elif gender not in ('male', 'female', 'other'):
        flash('Please choose a valid option.', 'danger')
    elif User.query.filter(User.id != user.id, or_(func.lower(User.email) == email,
                                                    User.user_id == email)).first():
        flash('That email is already used by another account.', 'danger')
    elif email != user.email.lower() and \
            not check_password_hash(user.password, request.form.get('current_password') or ''):
        flash('Enter your current password to change your email.', 'danger')
    else:
        if email != user.email.lower():
            user.email = user.user_id = email
        user.gender = gender
        db.session.commit()
        flash('Account details saved.', 'success')
    return redirect(url_for('settings') + '#account')


@app.route('/settings/password', methods=['POST'])
@login_required
def settings_password():
    user = g.user
    current = request.form.get('current_password') or ''
    new = request.form.get('new_password') or ''
    confirm = request.form.get('confirm_password') or ''
    if not check_password_hash(user.password, current):
        flash('Your current password is incorrect.', 'danger')
    elif len(new) < 6:
        flash('Your new password must be at least 6 characters.', 'danger')
    elif new != confirm:
        flash("The new passwords don't match.", 'danger')
    else:
        user.password = generate_password_hash(new)
        db.session.commit()
        flash('Password changed. 🔒', 'success')
    return redirect(url_for('settings') + '#security')


@app.route('/settings/export')
@login_required
def export_data():
    user = g.user
    data = {
        'exported_at': isodate_filter(datetime.utcnow()),
        'profile': {
            'first_name': user.first_name, 'last_name': user.last_name,
            'username': user.username, 'email': user.email, 'bio': user.bio,
            'location': user.location, 'website': user.website,
            'joined': isodate_filter(user.created_at),
        },
        'posts': [{'id': p.id, 'title': p.title, 'content': p.content,
                   'date_posted': isodate_filter(p.date_posted)}
                  for p in Post.query.filter_by(user_id=user.id).order_by(Post.id)],
        'comments': [{'id': c.id, 'post_id': c.post_id, 'content': c.content,
                      'date_created': isodate_filter(c.date_created)}
                     for c in Comment.query.filter_by(user_id=user.id).order_by(Comment.id)],
        'following': [u.handle for u in User.query.join(Follow, Follow.followed_id == User.id)
                      .filter(Follow.follower_id == user.id)],
    }
    response = jsonify(data)
    response.headers['Content-Disposition'] = \
        f'attachment; filename=postfy-{user.handle}-export.json'
    return response


def purge_user(user):
    for post in Post.query.filter_by(user_id=user.id).all():
        purge_post(post)
    comment_ids = [cid for (cid,) in db.session.query(Comment.id).filter_by(user_id=user.id)]
    if comment_ids:
        Notification.query.filter(Notification.comment_id.in_(comment_ids)) \
            .delete(synchronize_session=False)
    Comment.query.filter_by(user_id=user.id).delete(synchronize_session=False)
    Reaction.query.filter_by(user_id=user.id).delete(synchronize_session=False)
    Bookmark.query.filter_by(user_id=user.id).delete(synchronize_session=False)
    Follow.query.filter(or_(Follow.follower_id == user.id, Follow.followed_id == user.id)) \
        .delete(synchronize_session=False)
    Notification.query.filter(or_(Notification.user_id == user.id,
                                  Notification.actor_id == user.id)) \
        .delete(synchronize_session=False)
    Message.query.filter(or_(Message.sender_id == user.id, Message.recipient_id == user.id)) \
        .delete(synchronize_session=False)
    Report.query.filter_by(user_id=user.id).update({'user_id': None}, synchronize_session=False)
    delete_upload('UPLOAD_FOLDER', user.profile_picture)
    delete_upload('COVER_FOLDER', user.cover_picture)
    db.session.flush()
    User.query.filter_by(id=user.id).delete(synchronize_session=False)


@app.route('/settings/delete', methods=['POST'])
@login_required
def delete_account():
    user = g.user
    if not check_password_hash(user.password, request.form.get('password') or ''):
        flash('Incorrect password — your account was not deleted.', 'danger')
        return redirect(url_for('settings') + '#danger')
    purge_user(user)
    db.session.commit()
    session.pop('user_id', None)
    flash('Your account and all of your content have been deleted. Take care! 👋', 'info')
    return redirect(url_for('home'))


# ---------------------------------------------------------------------------
# JSON APIs used by the front-end
# ---------------------------------------------------------------------------

@app.route('/api/counts')
@login_required
def api_counts():
    return jsonify(unread_counts())


@app.route('/api/feed/new')
@login_required
def api_feed_new():
    after = request.args.get('after', 0, type=int)
    count = Post.query.filter(Post.id > after, Post.user_id != g.user.id).count()
    return jsonify(count=count)


@app.route('/api/username-available')
def api_username_available():
    username = (request.args.get('username') or '').strip().lower().lstrip('@')
    error = validate_username(username, g.user.id if g.user else None)
    return jsonify(available=error is None, message=error or f'@{username} is available')


def user_json(user):
    return {'name': user.full_name, 'handle': user.handle, 'initials': user.initials,
            'hue': user.avatar_hue, 'avatar': user.avatar_url,
            'url': url_for('user_profile', username=user.handle)}


@app.route('/api/search/suggest')
def api_search_suggest():
    q = (request.args.get('q') or '').strip()
    if not q:
        return jsonify(users=[], tags=[])
    users = [] if q.startswith('#') else [user_json(u) for u in search_users(q, 6)]
    tags = [] if q.startswith('@') else \
        [{'name': t, 'count': n, 'url': url_for('tag', name=t)} for t, n in search_tags(q, 4)]
    return jsonify(users=users, tags=tags)


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

@app.route('/submit_report', methods=['POST'])
def submit_report():
    title = (request.form.get('report_title') or '').strip()
    content = (request.form.get('report_content') or '').strip()
    email = (request.form.get('report_email') or '').strip()
    post_id = request.form.get('post_id', type=int)

    if not title or not content or (not g.user and not email):
        message = 'Please fill in all the fields.'
        return json_or_redirect({'error': message}, message, 'danger', 400,
                                target=back_url('home'))

    if post_id and db.session.get(Post, post_id):
        title = f'[Post #{post_id}] {title}'
        content = f"{content}\n\nReported post: {url_for('post_detail', post_id=post_id, _external=True)}"

    # Create new report
    new_report = Report(
        title=title[:255],
        content=content
    )

    # If user is logged in, link the report to their account
    if g.user:
        new_report.user_id = g.user.id
    # Otherwise, use the provided email
    else:
        new_report.email = email

    db.session.add(new_report)
    db.session.commit()

    return json_or_redirect(
        {'ok': True},
        'Your report has been submitted. Thank you for helping improve our community!',
        target=back_url('home'))


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(e):
    if wants_json() or request.path.startswith('/api/'):
        return jsonify(error='Not found'), 404
    return render_template('error.html', code=404, title="This page doesn't exist",
                           message="The link may be broken, or the page may have been removed."), 404


@app.errorhandler(413)
def too_large(e):
    message = 'That file is too large — the limit is 16 MB.'
    if wants_json():
        return jsonify(error=message), 413
    flash(message, 'danger')
    return redirect(back_url())


@app.errorhandler(500)
def server_error(e):
    db.session.rollback()
    if wants_json():
        return jsonify(error='Something went wrong on our side. Please try again.'), 500
    return render_template('error.html', code=500, title='Something went wrong',
                           message="We hit an unexpected error. Please try again in a moment."), 500


@app.route('/manifest.webmanifest')
def manifest():
    return Response(render_template('manifest.webmanifest'),
                    mimetype='application/manifest+json')


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@app.cli.command('seed-demo')
def seed_demo_command():
    """Fill the database with demo users, posts and conversations."""
    import demo_data
    created = demo_data.seed(db, app)
    print(f'Demo data ready: {created}')


if __name__ == '__main__':
    app.run(debug=True)
