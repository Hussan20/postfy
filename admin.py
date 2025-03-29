from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta

# Create a Blueprint for admin routes
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# Placeholder for db
db = None
AdminUser = None

# Admin authentication decorator


def admin_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Please log in to access the admin area', 'warning')
            return redirect(url_for('admin.login'))

        # Check if admin session has expired (optional session timeout)
        if 'admin_last_activity' in session:
            last_activity = datetime.fromisoformat(
                session['admin_last_activity'])
            if datetime.utcnow() - last_activity > timedelta(minutes=30):  # 30-minute timeout
                session.pop('admin_id', None)
                session.pop('admin_last_activity', None)
                flash('Your session has expired. Please log in again.', 'warning')
                return redirect(url_for('admin.login'))

        # Update last activity timestamp
        session['admin_last_activity'] = datetime.utcnow().isoformat()

        return f(*args, **kwargs)
    return decorated_function

# Define function to create AdminUser model


def create_admin_model(db_instance):
    global AdminUser, db
    db = db_instance

    class AdminUserClass(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(50), unique=True, nullable=False)
        email = db.Column(db.String(120), unique=True, nullable=False)
        password = db.Column(db.String(200), nullable=False)
        is_active = db.Column(db.Boolean, default=True, nullable=False)
        role = db.Column(db.String(20), nullable=False, default='admin')
        last_login = db.Column(db.DateTime, nullable=True)
        created_at = db.Column(db.DateTime, default=datetime.utcnow)

        def __repr__(self):
            return f'<AdminUser {self.username}>'

    AdminUser = AdminUserClass
    return AdminUser

# Admin login route


@admin_bp.route('/login', methods=['GET', 'POST'])
def login():
    # If already logged in, redirect to admin dashboard
    if 'admin_id' in session:
        return redirect(url_for('admin.dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        admin = AdminUser.query.filter_by(username=username).first()

        # Validate admin credentials
        if admin and admin.is_active and check_password_hash(admin.password, password):
            session['admin_id'] = admin.id
            session['admin_username'] = admin.username
            session['admin_last_activity'] = datetime.utcnow().isoformat()

            # Update last login time
            admin.last_login = datetime.utcnow()
            db.session.commit()

            flash('You are now logged in as admin', 'success')
            return redirect(url_for('admin.dashboard'))
        else:
            flash('Invalid credentials or inactive account', 'danger')

    return render_template('admin/login.html')

# Admin logout route


@admin_bp.route('/logout')
def logout():
    session.pop('admin_id', None)
    session.pop('admin_username', None)
    session.pop('admin_last_activity', None)
    flash('You have been logged out from the admin area', 'info')
    return redirect(url_for('admin.login'))

# Admin dashboard (protected route)


@admin_bp.route('/')
@admin_login_required
def dashboard():
    # Get statistics using raw SQL queries

    # Get total users
    result = db.session.execute(db.text("SELECT COUNT(*) FROM user"))
    total_users = result.scalar()

    # Get total posts
    result = db.session.execute(db.text("SELECT COUNT(*) FROM post"))
    total_posts = result.scalar()

    # Since there's no created_at field, we'll use a placeholder for new users today
    new_users_today = 0

    # Get report count (placeholder for future implementation)
    report_count = 0

    # Get recent user registrations (last 5)
    recent_users = db.session.execute(
        db.text("""
            SELECT id, first_name, last_name, email
            FROM user 
            ORDER BY id DESC LIMIT 5
        """)
    ).fetchall()

    # Get recent posts (last 5)
    recent_posts = db.session.execute(
        db.text("""
            SELECT p.id, p.title, p.date_posted, 
                   u.first_name, u.last_name
            FROM post p
            JOIN user u ON p.user_id = u.id
            ORDER BY p.date_posted DESC LIMIT 5
        """)
    ).fetchall()

    return render_template('admin/dashboard.html',
                           total_users=total_users,
                           total_posts=total_posts,
                           new_users_today=new_users_today,
                           report_count=report_count,
                           recent_users=recent_users,
                           recent_posts=recent_posts)

# User management routes


@admin_bp.route('/users')
@admin_login_required
def users():
    # Get all users with optional search/filter
    search_term = request.args.get('search', '')

    if search_term:
        # Search by name or email
        users_data = db.session.execute(
            db.text("""
                SELECT id, first_name, last_name, email, gender, user_id 
                FROM user 
                WHERE first_name LIKE :search OR last_name LIKE :search OR email LIKE :search
                ORDER BY id DESC
            """),
            {"search": f"%{search_term}%"}
        ).fetchall()
    else:
        # Get all users
        users_data = db.session.execute(
            db.text("""
                SELECT id, first_name, last_name, email, gender, user_id 
                FROM user 
                ORDER BY id DESC
            """)
        ).fetchall()

    # Count posts for each user
    user_post_counts = {}
    for user in users_data:
        post_count = db.session.execute(
            db.text("SELECT COUNT(*) FROM post WHERE user_id = :user_id"),
            {"user_id": user.id}
        ).scalar()
        user_post_counts[user.id] = post_count

    return render_template('admin/users.html',
                           users=users_data,
                           post_counts=user_post_counts,
                           search_term=search_term)


@admin_bp.route('/users/view/<int:user_id>')
@admin_login_required
def user_view(user_id):
    # Get user details
    user_data = db.session.execute(
        db.text("""
            SELECT id, first_name, last_name, email, gender, user_id, profile_picture
            FROM user 
            WHERE id = :user_id
        """),
        {"user_id": user_id}
    ).fetchone()

    if not user_data:
        flash('User not found', 'danger')
        return redirect(url_for('admin.users'))

    # Get user's posts
    posts_data = db.session.execute(
        db.text("""
            SELECT id, title, content, date_posted
            FROM post 
            WHERE user_id = :user_id
            ORDER BY date_posted DESC
        """),
        {"user_id": user_id}
    ).fetchall()

    # Count total posts
    post_count = len(posts_data)

    return render_template('admin/user_view.html',
                           user=user_data,
                           posts=posts_data,
                           post_count=post_count)


@admin_bp.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@admin_login_required
def user_edit(user_id):
    # Get user details
    user = db.session.execute(
        db.text("""
            SELECT id, first_name, last_name, email, gender, user_id
            FROM user 
            WHERE id = :user_id
        """),
        {"user_id": user_id}
    ).fetchone()

    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('admin.users'))

    if request.method == 'POST':
        # Get form data
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        gender = request.form['gender']
        # For future implementation
        status = request.form.get('status', 'active')

        # Check if email is changed and already exists
        if email != user.email:
            existing_email = db.session.execute(
                db.text(
                    "SELECT id FROM user WHERE email = :email AND id != :user_id"),
                {"email": email, "user_id": user_id}
            ).fetchone()

            if existing_email:
                flash('Email already exists for another user', 'danger')
                return render_template('admin/user_edit.html', user=user)

        # Update user
        db.session.execute(
            db.text("""
                UPDATE user 
                SET first_name = :first_name, last_name = :last_name, 
                    email = :email, gender = :gender
                WHERE id = :user_id
            """),
            {
                "first_name": first_name,
                "last_name": last_name,
                "email": email,
                "gender": gender,
                "user_id": user_id
            }
        )

        # If password is provided, update it
        new_password = request.form.get('new_password')
        if new_password:
            hashed_password = generate_password_hash(new_password)
            db.session.execute(
                db.text("UPDATE user SET password = :password WHERE id = :user_id"),
                {"password": hashed_password, "user_id": user_id}
            )

        db.session.commit()
        flash('User information updated successfully', 'success')
        return redirect(url_for('admin.user_view', user_id=user_id))

    return render_template('admin/user_edit.html', user=user)


@admin_bp.route('/users/delete/<int:user_id>', methods=['POST'])
@admin_login_required
def user_delete(user_id):
    # Check if user exists
    user = db.session.execute(
        db.text("SELECT id, first_name, last_name FROM user WHERE id = :user_id"),
        {"user_id": user_id}
    ).fetchone()

    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('admin.users'))

    # Delete user's posts first
    db.session.execute(
        db.text("DELETE FROM post WHERE user_id = :user_id"),
        {"user_id": user_id}
    )

    # Delete user
    db.session.execute(
        db.text("DELETE FROM user WHERE id = :user_id"),
        {"user_id": user_id}
    )

    db.session.commit()
    flash(
        f'User {user.first_name} {user.last_name} and all their posts have been deleted', 'success')
    return redirect(url_for('admin.users'))

# Create first admin user command


def create_admin_cli(app):
    @app.cli.command('create-admin')
    def create_admin():
        """Create initial admin user"""
        username = input('Enter admin username: ')
        email = input('Enter admin email: ')
        password = input('Enter admin password: ')

        # Check if admin already exists
        existing_admin = AdminUser.query.filter(
            (AdminUser.username == username) | (AdminUser.email == email)
        ).first()

        if existing_admin:
            print('An admin with that username or email already exists')
            return

        # Create new admin
        new_admin = AdminUser(
            username=username,
            email=email,
            password=generate_password_hash(password),
            is_active=True,
            created_at=datetime.utcnow()
        )

        db.session.add(new_admin)
        db.session.commit()
        print(f'Admin user {username} created successfully')

# Initialization function


def initialize_admin(app, sqlalchemy_db):
    global db

    # Create AdminUser model
    create_admin_model(sqlalchemy_db)

    # Register blueprint
    app.register_blueprint(admin_bp)

    # Register CLI command
    create_admin_cli(app)

    # Ensure model is registered with SQLAlchemy
    with app.app_context():
        db.create_all()

    return admin_bp
