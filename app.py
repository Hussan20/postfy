from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
from flask_migrate import Migrate
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)


APP_VERSION = "Postfy-0.1_alpha"

app.config['UPLOAD_FOLDER'] = 'static/profile_pics'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower(
           ) in app.config['ALLOWED_EXTENSIONS']


@app.context_processor
def inject_version():
    return dict(APP_VERSION=APP_VERSION)


app.secret_key = 'your_secret_key'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


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

    def __repr__(self):
        return f'<User {self.first_name} {self.last_name}>'


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date_posted = db.Column(
        db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='posts', lazy=True)

    def __repr__(self):
        return f'<Post {self.title}>'


with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/create_post', methods=['GET', 'POST'])
@login_required
def create_post():
    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        post_title = request.form['post_title']
        post_content = request.form['post_content']

        new_post = Post(
            title=post_title,
            content=post_content,
            user_id=user.id,
            date_posted=datetime.utcnow()
        )
        db.session.add(new_post)
        db.session.commit()

        flash("Post created successfully!", 'success')
        return redirect(url_for('newposts'))

    session['user_name'] = f"{user.first_name} {user.last_name}"

    return render_template('create_post.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = generate_password_hash(
            request.form['password'])
        gender = request.form['gender']

        # Handle profile picture upload
        profile_pic = request.files.get('profile_picture')
        profile_pic_filename = 'default.jpg'  # Default image

        if profile_pic and profile_pic.filename != '' and allowed_file(profile_pic.filename):
            # Create a secure filename
            filename = secure_filename(profile_pic.filename)
            # Make filename unique by adding timestamp
            filename = f"{int(datetime.utcnow().timestamp())}_{filename}"
            # Save the file
            profile_pic.save(os.path.join(
                app.config['UPLOAD_FOLDER'], filename))
            profile_pic_filename = filename

        existing_user = User.query.filter((User.email == email)).first()
        if existing_user:
            flash("Email already exists!", 'danger')
            return redirect(url_for('signup'))

        new_user = User(
            first_name=first_name,
            last_name=last_name,
            user_id=email,
            email=email,
            password=password,
            gender=gender,
            profile_picture=profile_pic_filename
        )
        db.session.add(new_user)
        db.session.commit()

        flash("Account created successfully!", 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash("Login successful!", 'success')
            return redirect(url_for('newposts'))
        else:
            flash("Invalid credentials!", 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("You have been logged out", 'info')
    return redirect(url_for('login'))


@app.route('/newposts')
@login_required
def newposts():
    posts = (
        Post.query.join(User)
        .add_columns(
            Post.id,
            Post.title,
            Post.content,
            Post.date_posted,
            Post.user_id,
            User.first_name,
            User.last_name
        )
        .order_by(Post.date_posted.desc())
        .all()
    )
    return render_template('newpost.html', posts=posts, current_user_id=session['user_id'])


@app.route('/profile')
@login_required
def profile():
    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)

# --------------------------------------------------------------------#


@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)

    if post.user_id != session['user_id']:
        flash("You can only edit your own posts!", 'danger')
        return redirect(url_for('newposts'))

    if request.method == 'POST':
        post.title = request.form['post_title']
        post.content = request.form['post_content']

        db.session.commit()
        flash("Post updated successfully!", 'success')
        return redirect(url_for('newposts'))

    return render_template('edit_post.html', post=post)


@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)

    if post.user_id != session['user_id']:
        flash("You can only delete your own posts!", 'danger')
        return redirect(url_for('newposts'))

    db.session.delete(post)
    db.session.commit()

    flash("Post deleted successfully!", 'success')
    return redirect(url_for('newposts'))


with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
