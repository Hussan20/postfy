from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
from flask_migrate import Migrate

app = Flask(__name__)


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

        existing_user = User.query.filter((User.email == email)).first()
        if existing_user:
            flash("Email already exists!", 'danger')
            return redirect(url_for('signup'))

        new_user = User(first_name=first_name, last_name=last_name,
                        user_id=email, email=email, password=password, gender=gender)
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
        .add_columns(Post.id, Post.title, Post.content, Post.date_posted, User.first_name, User.last_name)
        .order_by(Post.date_posted.desc())
        .all()
    )
    return render_template('newpost.html', posts=posts)


@app.route('/profile')
@login_required
def profile():
    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)


with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
