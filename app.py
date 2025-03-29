import admin
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
from flask_migrate import Migrate
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)


APP_VERSION = "Postfy-0.3_alpha"

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

# Import admin module after app and db are created
admin.initialize_admin(app, db)


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
    # Get all posts with user information
    posts_data = db.session.query(
        Post,
        User.first_name,
        User.last_name,
        User.profile_picture
    ).join(User, Post.user_id == User.id).order_by(Post.date_posted.desc()).all()

    # Format posts for the template and add reaction counts
    formatted_posts = []
    for post_obj, first_name, last_name, profile_picture in posts_data:
        # Count likes and dislikes for this post
        like_count = Reaction.query.filter_by(
            post_id=post_obj.id, reaction_type='like').count()
        dislike_count = Reaction.query.filter_by(
            post_id=post_obj.id, reaction_type='dislike').count()

        # Check if current user has reacted to this post
        user_reaction = Reaction.query.filter_by(
            post_id=post_obj.id,
            user_id=session['user_id']
        ).first()

        # Get comments for this post
        comments_data = db.session.query(
            Comment,
            User.id.label('user_id'),
            User.first_name,
            User.last_name,
            User.profile_picture
        ).join(User, Comment.user_id == User.id).filter(
            Comment.post_id == post_obj.id
        ).order_by(Comment.date_created.asc()).all()

        # Format comments
        formatted_comments = []
        for comment, user_id, comment_first_name, comment_last_name, comment_profile_pic in comments_data:
            formatted_comments.append({
                'id': comment.id,
                'content': comment.content,
                'date_created': comment.date_created,
                'user_id': user_id,
                'first_name': comment_first_name,
                'last_name': comment_last_name,
                'profile_picture': comment_profile_pic
            })

        formatted_posts.append({
            'id': post_obj.id,
            'title': post_obj.title,
            'content': post_obj.content,
            'date_posted': post_obj.date_posted,
            'user_id': post_obj.user_id,
            'first_name': first_name,
            'last_name': last_name,
            'profile_picture': profile_picture,
            'like_count': like_count,
            'dislike_count': dislike_count,
            'user_reaction': user_reaction.reaction_type if user_reaction else None,
            'comments': formatted_comments,
            'comment_count': len(formatted_comments)
        })

    return render_template('newpost.html', posts=formatted_posts, current_user_id=session['user_id'])


@app.route('/profile')
@login_required
def profile():
    user = User.query.get(session['user_id'])

    # Get reaction stats
    like_count = Reaction.query.filter_by(
        user_id=user.id, reaction_type='like').count()
    dislike_count = Reaction.query.filter_by(
        user_id=user.id, reaction_type='dislike').count()

    # Get comment stats
    comment_count = Comment.query.filter_by(user_id=user.id).count()

    return render_template('profile.html', user=user, like_count=like_count, dislike_count=dislike_count, comment_count=comment_count)


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

    # Delete all reactions to this post first
    Reaction.query.filter_by(post_id=post_id).delete()

    # Delete all comments on this post
    Comment.query.filter_by(post_id=post_id).delete()

    # Then delete the post
    db.session.delete(post)
    db.session.commit()

    flash("Post deleted successfully!", 'success')
    return redirect(url_for('newposts'))


@app.route('/add_comment/<int:post_id>', methods=['POST'])
@login_required
def add_comment(post_id):
    post = Post.query.get_or_404(post_id)
    comment_content = request.form.get('comment_content')

    if not comment_content or comment_content.strip() == '':
        flash("Comment cannot be empty!", 'danger')
        return redirect(url_for('newposts'))

    new_comment = Comment(
        content=comment_content,
        post_id=post_id,
        user_id=session['user_id'],
        date_created=datetime.utcnow()
    )

    db.session.add(new_comment)
    db.session.commit()

    flash("Comment added successfully!", 'success')
    return redirect(url_for('newposts'))


@app.route('/edit_comment/<int:comment_id>', methods=['GET', 'POST'])
@login_required
def edit_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)

    # Check if the current user is the author of the comment
    if comment.user_id != session['user_id']:
        flash("You can only edit your own comments!", 'danger')
        return redirect(url_for('newposts'))

    if request.method == 'POST':
        comment_content = request.form.get('comment_content')

        if not comment_content or comment_content.strip() == '':
            flash("Comment cannot be empty!", 'danger')
            return redirect(url_for('edit_comment', comment_id=comment_id))

        comment.content = comment_content
        db.session.commit()

        flash("Comment updated successfully!", 'success')
        return redirect(url_for('newposts'))

    # Get post information for context
    post = Post.query.get(comment.post_id)

    return render_template('edit_comment.html', comment=comment, post=post)


@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)

    # Check if the current user is the author of the comment
    if comment.user_id != session['user_id']:
        flash("You can only delete your own comments!", 'danger')
        return redirect(url_for('newposts'))

    db.session.delete(comment)
    db.session.commit()

    flash("Comment deleted successfully!", 'success')
    return redirect(url_for('newposts'))


@app.route('/react/<string:reaction_type>/<int:post_id>', methods=['POST'])
@login_required
def react_to_post(reaction_type, post_id):
    if reaction_type not in ['like', 'dislike']:
        flash('Invalid reaction type!', 'danger')
        return redirect(url_for('newposts'))

    # Check if post exists
    post = Post.query.get_or_404(post_id)
    user_id = session['user_id']

    # Check if user already reacted to this post
    existing_reaction = Reaction.query.filter_by(
        post_id=post_id,
        user_id=user_id
    ).first()

    if existing_reaction:
        if existing_reaction.reaction_type == reaction_type:
            # If the same reaction already exists, remove it (toggle off)
            db.session.delete(existing_reaction)
            flash(f'{reaction_type.capitalize()} removed!', 'success')
        else:
            # If different reaction, update it
            existing_reaction.reaction_type = reaction_type
            flash(f'Changed to {reaction_type}!', 'success')
    else:
        # Create new reaction
        new_reaction = Reaction(
            post_id=post_id,
            user_id=user_id,
            reaction_type=reaction_type
        )
        db.session.add(new_reaction)
        flash(f'{reaction_type.capitalize()} added!', 'success')

    db.session.commit()

    # Redirect back to the page where the reaction was made
    return redirect(request.referrer or url_for('newposts'))


if __name__ == '__main__':
    app.run(debug=True)
