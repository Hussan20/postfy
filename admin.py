from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import json
import os

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

    # New users registered since midnight (UTC)
    today_start = datetime.utcnow().replace(
        hour=0, minute=0, second=0, microsecond=0)
    new_users_today = db.session.execute(
        db.text("SELECT COUNT(*) FROM user WHERE created_at >= :today"),
        {"today": today_start}
    ).scalar() or 0

    # Reports still waiting for a moderator
    report_count = db.session.execute(
        db.text("SELECT COUNT(*) FROM report WHERE status = 'pending'")
    ).scalar() or 0

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

    # Delete everything attached to the user's posts, then the posts
    post_ids = "SELECT id FROM post WHERE user_id = :user_id"
    for table in ('comment', 'reaction', 'bookmark', 'notification'):
        db.session.execute(
            db.text(f"DELETE FROM {table} WHERE post_id IN ({post_ids})"),
            {"user_id": user_id}
        )
    db.session.execute(
        db.text("DELETE FROM post WHERE user_id = :user_id"),
        {"user_id": user_id}
    )

    # Delete the user's own activity elsewhere on the site
    cleanup = [
        "DELETE FROM notification WHERE comment_id IN (SELECT id FROM comment WHERE user_id = :user_id)",
        "DELETE FROM comment WHERE user_id = :user_id",
        "DELETE FROM reaction WHERE user_id = :user_id",
        "DELETE FROM bookmark WHERE user_id = :user_id",
        "DELETE FROM follow WHERE follower_id = :user_id OR followed_id = :user_id",
        "DELETE FROM notification WHERE user_id = :user_id OR actor_id = :user_id",
        "DELETE FROM message WHERE sender_id = :user_id OR recipient_id = :user_id",
        "UPDATE report SET user_id = NULL WHERE user_id = :user_id",
    ]
    for statement in cleanup:
        db.session.execute(db.text(statement), {"user_id": user_id})

    # Delete user
    db.session.execute(
        db.text("DELETE FROM user WHERE id = :user_id"),
        {"user_id": user_id}
    )

    db.session.commit()
    flash(
        f'User {user.first_name} {user.last_name} and all their posts have been deleted', 'success')
    return redirect(url_for('admin.users'))

# Post management routes


@admin_bp.route('/posts')
@admin_login_required
def posts():
    # Get all posts with optional search/filter
    search_term = request.args.get('search', '')

    if search_term:
        # Search by title or content
        posts_data = db.session.execute(
            db.text("""
                SELECT p.id, p.title, p.content, p.date_posted, 
                       u.first_name, u.last_name, u.id as user_id
                FROM post p
                JOIN user u ON p.user_id = u.id
                WHERE p.title LIKE :search OR p.content LIKE :search
                ORDER BY p.date_posted DESC
            """),
            {"search": f"%{search_term}%"}
        ).fetchall()
    else:
        # Get all posts
        posts_data = db.session.execute(
            db.text("""
                SELECT p.id, p.title, p.content, p.date_posted, 
                       u.first_name, u.last_name, u.id as user_id
                FROM post p
                JOIN user u ON p.user_id = u.id
                ORDER BY p.date_posted DESC
            """)
        ).fetchall()

    # Get post analytics
    total_posts = len(posts_data)

    # Calculate average post length
    total_content_length = sum(len(post.content or '')
                               for post in posts_data) if posts_data else 0
    avg_post_length = total_content_length / total_posts if total_posts > 0 else 0

    # Get unique author count
    unique_authors = len(
        set(post.user_id for post in posts_data)) if posts_data else 0

    # Get posts per day (last 7 days)
    posts_by_day = {}
    today = datetime.utcnow().date()
    for i in range(7):
        day = today - timedelta(days=i)
        day_str = day.strftime('%Y-%m-%d')
        posts_by_day[day_str] = 0

    # Count posts per day
    for post in posts_data:
        if post.date_posted:
            # Handle post.date_posted as a string
            # Extract just the date part (YYYY-MM-DD)
            post_date = str(post.date_posted).split()[0]
            if post_date in posts_by_day:
                posts_by_day[post_date] += 1

    # Convert to list for template
    posts_per_day = [{"date": date, "count": count}
                     for date, count in posts_by_day.items()]
    posts_per_day.reverse()  # Chronological order

    return render_template('admin/posts.html',
                           posts=posts_data,
                           search_term=search_term,
                           total_posts=total_posts,
                           avg_post_length=avg_post_length,
                           unique_authors=unique_authors,
                           posts_per_day=posts_per_day,
                           today=today)


@admin_bp.route('/posts/view/<int:post_id>')
@admin_login_required
def post_view(post_id):
    # Get post details with author information
    post_data = db.session.execute(
        db.text("""
            SELECT p.id, p.title, p.content, p.date_posted, 
                   u.first_name, u.last_name, u.id as user_id
            FROM post p
            JOIN user u ON p.user_id = u.id
            WHERE p.id = :post_id
        """),
        {"post_id": post_id}
    ).fetchone()

    if not post_data:
        flash('Post not found', 'danger')
        return redirect(url_for('admin.posts'))

    # Get reaction counts
    like_count = db.session.execute(
        db.text("""
            SELECT COUNT(*) FROM reaction 
            WHERE post_id = :post_id AND reaction_type = 'like'
        """),
        {"post_id": post_id}
    ).scalar() or 0

    dislike_count = db.session.execute(
        db.text("""
            SELECT COUNT(*) FROM reaction 
            WHERE post_id = :post_id AND reaction_type = 'dislike'
        """),
        {"post_id": post_id}
    ).scalar() or 0

    # Get comments for the post
    comments = db.session.execute(
        db.text("""
            SELECT c.id, c.content, c.date_created, 
                   u.id as user_id, u.first_name, u.last_name, u.profile_picture
            FROM comment c
            JOIN user u ON c.user_id = u.id
            WHERE c.post_id = :post_id
            ORDER BY c.date_created DESC
        """),
        {"post_id": post_id}
    ).fetchall()

    # Count total comments
    comment_count = len(comments)

    return render_template('admin/post_view.html',
                           post=post_data,
                           like_count=like_count,
                           dislike_count=dislike_count,
                           comments=comments,
                           comment_count=comment_count)


@admin_bp.route('/posts/edit/<int:post_id>', methods=['GET', 'POST'])
@admin_login_required
def post_edit(post_id):
    # Get post details
    post = db.session.execute(
        db.text("""
            SELECT p.id, p.title, p.content, p.user_id
            FROM post p
            WHERE p.id = :post_id
        """),
        {"post_id": post_id}
    ).fetchone()

    if not post:
        flash('Post not found', 'danger')
        return redirect(url_for('admin.posts'))

    if request.method == 'POST':
        # Get form data
        title = request.form['title']
        content = request.form['content']

        # Update post
        db.session.execute(
            db.text("""
                UPDATE post 
                SET title = :title, content = :content
                WHERE id = :post_id
            """),
            {
                "title": title,
                "content": content,
                "post_id": post_id
            }
        )

        db.session.commit()
        flash('Post updated successfully', 'success')
        return redirect(url_for('admin.post_view', post_id=post_id))

    return render_template('admin/post_edit.html', post=post)


@admin_bp.route('/posts/delete/<int:post_id>', methods=['POST'])
@admin_login_required
def post_delete(post_id):
    # Check if post exists
    post = db.session.execute(
        db.text("SELECT id, title FROM post WHERE id = :post_id"),
        {"post_id": post_id}
    ).fetchone()

    if not post:
        flash('Post not found', 'danger')
        return redirect(url_for('admin.posts'))

    # Delete comments, reactions, bookmarks and notifications for the post
    db.session.execute(
        db.text("DELETE FROM notification WHERE comment_id IN "
                "(SELECT id FROM comment WHERE post_id = :post_id)"),
        {"post_id": post_id}
    )
    for table in ('comment', 'reaction', 'bookmark', 'notification'):
        db.session.execute(
            db.text(f"DELETE FROM {table} WHERE post_id = :post_id"),
            {"post_id": post_id}
        )

    # Delete post
    db.session.execute(
        db.text("DELETE FROM post WHERE id = :post_id"),
        {"post_id": post_id}
    )

    db.session.commit()
    flash(f'Post "{post.title}" has been deleted', 'success')
    return redirect(url_for('admin.posts'))

# Create first admin user command

# Reports management routes


@admin_bp.route('/reports')
@admin_login_required
def reports():
    # Get all reports with optional filter
    status_filter = request.args.get('status', '')

    if status_filter:
        # Filter by status
        reports_data = db.session.execute(
            db.text("""
                SELECT r.id, r.title, r.content, r.email, r.user_id, r.status, r.date_created,
                       u.first_name, u.last_name
                FROM report r
                LEFT JOIN user u ON r.user_id = u.id
                WHERE r.status = :status
                ORDER BY r.date_created DESC
            """),
            {"status": status_filter}
        ).fetchall()
    else:
        # Get all reports
        reports_data = db.session.execute(
            db.text("""
                SELECT r.id, r.title, r.content, r.email, r.user_id, r.status, r.date_created,
                       u.first_name, u.last_name 
                FROM report r
                LEFT JOIN user u ON r.user_id = u.id
                ORDER BY r.date_created DESC
            """)
        ).fetchall()

    # Get counts for each status
    pending_count = db.session.execute(
        db.text("SELECT COUNT(*) FROM report WHERE status = 'pending'")
    ).scalar() or 0

    reviewed_count = db.session.execute(
        db.text("SELECT COUNT(*) FROM report WHERE status = 'reviewed'")
    ).scalar() or 0

    resolved_count = db.session.execute(
        db.text("SELECT COUNT(*) FROM report WHERE status = 'resolved'")
    ).scalar() or 0

    return render_template('admin/reports.html',
                           reports=reports_data,
                           status_filter=status_filter,
                           pending_count=pending_count,
                           reviewed_count=reviewed_count,
                           resolved_count=resolved_count)


@admin_bp.route('/reports/view/<int:report_id>')
@admin_login_required
def report_view(report_id):
    # Get report details
    report_data = db.session.execute(
        db.text("""
            SELECT r.id, r.title, r.content, r.email, r.user_id, r.status, r.date_created,
                   u.first_name, u.last_name
            FROM report r
            LEFT JOIN user u ON r.user_id = u.id
            WHERE r.id = :report_id
        """),
        {"report_id": report_id}
    ).fetchone()

    if not report_data:
        flash('Report not found', 'danger')
        return redirect(url_for('admin.reports'))

    return render_template('admin/report_view.html', report=report_data)


@admin_bp.route('/reports/update-status/<int:report_id>', methods=['POST'])
@admin_login_required
def update_report_status(report_id):
    new_status = request.form['status']

    # Update report status
    db.session.execute(
        db.text("""
            UPDATE report
            SET status = :status
            WHERE id = :report_id
        """),
        {"status": new_status, "report_id": report_id}
    )

    db.session.commit()
    flash(f'Report status updated to {new_status}', 'success')
    return redirect(url_for('admin.report_view', report_id=report_id))


@admin_bp.route('/settings')
@admin_login_required
def settings():
    """Admin system settings page"""
    # Load current theme settings
    theme_settings = load_theme_settings()

    return render_template('admin/settings.html', theme_settings=theme_settings)


@admin_bp.route('/settings/theme', methods=['POST'])
@admin_login_required
def save_theme_settings():
    """Save theme settings"""
    # Get theme settings from form
    theme_settings = {
        'background_color': request.form.get('background_color', '#0b0d12'),
        'light_background_color': request.form.get('light_background_color', '#151922'),
        'text_color': request.form.get('text_color', '#e8eaf0'),
        'primary_color': request.form.get('primary_color', '#00b8f4')
    }

    # Save settings to file
    save_settings_to_file(theme_settings)

    # Generate CSS file
    generate_custom_css(theme_settings)

    flash('Theme settings updated successfully', 'success')
    return redirect(url_for('admin.settings'))

# Add these utility functions at the end of admin.py


def load_theme_settings():
    """Load theme settings from file"""
    # Get the app instance
    app = current_app._get_current_object()
    settings_file = os.path.join(
        app.static_folder, 'settings', 'theme_settings.json')

    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(settings_file), exist_ok=True)

    # Default settings
    default_settings = {
        'background_color': '#0b0d12',
        'light_background_color': '#151922',
        'text_color': '#e8eaf0',
        'primary_color': '#00b8f4'
    }

    # Try to load settings from file
    try:
        if os.path.exists(settings_file):
            with open(settings_file, 'r') as f:
                return json.load(f)
        return default_settings
    except Exception as e:
        print(f"Error loading theme settings: {e}")
        return default_settings


def save_settings_to_file(settings):
    """Save theme settings to file"""
    # Get the app instance
    app = current_app._get_current_object()
    settings_file = os.path.join(
        app.static_folder, 'settings', 'theme_settings.json')

    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(settings_file), exist_ok=True)

    try:
        with open(settings_file, 'w') as f:
            json.dump(settings, f, indent=4)
    except Exception as e:
        print(f"Error saving theme settings: {e}")


def generate_custom_css(settings):
    """Generate custom CSS from theme settings"""
    css_template = """/* Custom theme generated from admin settings */
:root {
    --dark-background: %(background_color)s;
    --light-background: %(light_background_color)s;
    --text-light: %(text_color)s;
    --neon-blue: %(primary_color)s;
    --shadow: rgba(0, 0, 0, 0.5);
}
"""

    css_content = css_template % settings

    # Get the app instance
    app = current_app._get_current_object()
    css_file = os.path.join(app.static_folder, 'css', 'custom_theme.css')

    try:
        with open(css_file, 'w') as f:
            f.write(css_content)
    except Exception as e:
        print(f"Error generating custom CSS: {e}")

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
