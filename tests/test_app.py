"""Postfy test suite.

Run with:  python -m unittest discover tests
Uses a throwaway SQLite database and temporary upload folders, so your real
instance/users.db and static/ files are never touched.
"""
import io
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest

TMP = tempfile.mkdtemp(prefix='postfy-tests-')
os.environ['DATABASE_URL'] = 'sqlite:///' + os.path.join(TMP, 'test.db')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as postfy  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402

app, db = postfy.app, postfy.db
User, Post, Comment, Reaction = postfy.User, postfy.Post, postfy.Comment, postfy.Reaction
Follow, Bookmark, Notification, Message = postfy.Follow, postfy.Bookmark, postfy.Notification, postfy.Message

PNG = (b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15'
       b'\xc4\x89\x00\x00\x00\rIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82')
JSON = {'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'}


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


class PostfyTestCase(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True, CSRF_ENABLED=False)
        for key in ('UPLOAD_FOLDER', 'COVER_FOLDER', 'POST_IMAGE_FOLDER'):
            folder = os.path.join(TMP, key.lower())
            os.makedirs(folder, exist_ok=True)
            app.config[key] = folder
        with app.app_context():
            db.drop_all()
            db.create_all()
            self.alice = self.make_user('alice', 'Alice', 'Smith')
            self.bob = self.make_user('bob', 'Bob', 'Jones')
        self.client = app.test_client()

    def make_user(self, username, first, last):
        user = User(first_name=first, last_name=last, user_id=f'{username}@example.com',
                    email=f'{username}@example.com', username=username,
                    password=generate_password_hash('secret123'), gender='other')
        db.session.add(user)
        db.session.commit()
        return user.id

    def login(self, user_id, client=None):
        with (client or self.client).session_transaction() as sess:
            sess['user_id'] = user_id

    def make_post(self, user_id, title='Hello', content='World'):
        with app.app_context():
            post = Post(title=title, content=content, user_id=user_id)
            db.session.add(post)
            db.session.commit()
            return post.id

    def count(self, model, **filters):
        with app.app_context():
            return model.query.filter_by(**filters).count()


class AuthTests(PostfyTestCase):
    def test_signup_logs_in_and_validates(self):
        r = self.client.post('/signup', data={
            'first_name': 'Carol', 'last_name': 'White', 'username': 'Carol_W',
            'email': 'CAROL@example.com', 'password': 'hunter22', 'gender': 'female'})
        self.assertEqual(r.status_code, 302)
        self.assertTrue(r.headers['Location'].endswith('/feed'))
        with app.app_context():
            carol = User.query.filter_by(username='carol_w').one()
            self.assertEqual(carol.email, 'carol@example.com')

        r = app.test_client().post('/signup', data={
            'first_name': 'X', 'last_name': 'Y', 'username': 'alice', 'email': 'alice@example.com',
            'password': '123', 'gender': 'male'})
        self.assertEqual(r.status_code, 400)
        page = r.get_data(as_text=True)
        self.assertIn('already taken', page)
        self.assertIn('already exists', page)
        self.assertIn('at least 6', page)

    def test_login_with_email_or_username_and_safe_next(self):
        r = self.client.post('/login', data={'email': 'alice@example.com', 'password': 'secret123',
                                             'next': '//evil.example.com'})
        self.assertTrue(r.headers['Location'].endswith('/feed'))
        c = app.test_client()
        r = c.post('/login', data={'email': '@bob', 'password': 'secret123', 'next': '/bookmarks'})
        self.assertTrue(r.headers['Location'].endswith('/bookmarks'))
        r = app.test_client().post('/login', data={'email': 'bob', 'password': 'nope'})
        self.assertEqual(r.status_code, 200)
        self.assertIn("don&#39;t match", r.get_data(as_text=True))

    def test_login_required_redirects_with_next_and_json_401(self):
        r = self.client.get('/bookmarks')
        self.assertIn('/login?next=/bookmarks', r.headers['Location'])
        r = self.client.post('/bookmark/1', headers=JSON)
        self.assertEqual(r.status_code, 401)

    def test_csrf_blocks_posts_without_token(self):
        app.config['CSRF_ENABLED'] = True
        self.login(self.alice)
        r = self.client.post('/create_post', data={'post_title': 't', 'post_content': 'c'}, headers=JSON)
        self.assertEqual(r.status_code, 400)
        self.client.get('/feed')
        with self.client.session_transaction() as sess:
            token = sess['_csrf_token']
        r = self.client.post('/create_post', data={'post_title': 't', 'post_content': 'c'},
                             headers={**JSON, 'X-CSRFToken': token})
        self.assertEqual(r.status_code, 200)


class PostTests(PostfyTestCase):
    def test_create_post_json_escapes_html_and_links_tags(self):
        self.login(self.alice)
        r = self.client.post('/create_post', headers=JSON, data={
            'post_title': 'Hi', 'post_content': '<script>alert(1)</script> #Design @bob https://example.com/x.'})
        data = r.get_json()
        self.assertTrue(data['ok'])
        self.assertNotIn('<script>', data['html'])
        self.assertIn('&lt;script&gt;', data['html'])
        self.assertIn('/tag/design', data['html'])
        self.assertIn('/u/bob', data['html'])
        self.assertIn('href="https://example.com/x"', data['html'])
        self.assertEqual(self.count(Notification, user_id=self.bob, kind='mention'), 1)

    def test_post_validation_and_image_upload(self):
        self.login(self.alice)
        r = self.client.post('/create_post', headers=JSON, data={'post_title': '', 'post_content': 'x'})
        self.assertEqual(r.status_code, 400)
        r = self.client.post('/create_post', headers=JSON, content_type='multipart/form-data', data={
            'post_title': 'Pic', 'post_content': 'x', 'post_image': (io.BytesIO(b'not an image'), 'evil.png')})
        self.assertEqual(r.status_code, 400)
        r = self.client.post('/create_post', headers=JSON, content_type='multipart/form-data', data={
            'post_title': 'Pic', 'post_content': 'x', 'post_image': (io.BytesIO(PNG), 'photo.png')})
        self.assertEqual(r.status_code, 200)
        with app.app_context():
            post = Post.query.filter_by(title='Pic').one()
            self.assertTrue(post.image.endswith('.png'))
            self.assertTrue(os.path.exists(os.path.join(app.config['POST_IMAGE_FOLDER'], post.image)))

    def test_only_owner_can_edit_or_delete(self):
        post_id = self.make_post(self.alice)
        self.login(self.bob)
        self.client.post(f'/edit_post/{post_id}', data={'post_title': 'Hacked', 'post_content': 'x'})
        r = self.client.post(f'/delete_post/{post_id}', headers=JSON)
        self.assertEqual(r.status_code, 403)
        self.login(self.alice)
        self.client.post(f'/edit_post/{post_id}', data={'post_title': 'Edited', 'post_content': 'y'})
        with app.app_context():
            self.assertEqual(db.session.get(Post, post_id).title, 'Edited')
        r = self.client.post(f'/delete_post/{post_id}', headers=JSON)
        self.assertTrue(r.get_json()['ok'])
        self.assertEqual(self.count(Post), 0)

    def test_feed_tabs_pagination_and_pages_render(self):
        for i in range(12):
            self.make_post(self.bob if i % 2 else self.alice, title=f'Post {i}', content=f'#topic{i % 3}')
        self.login(self.alice)
        for url in ['/feed', '/feed?tab=following', '/feed?tab=popular', '/u/bob', '/u/bob?tab=likes',
                    '/u/bob/followers', '/people', '/search?q=Post', '/search?q=b&type=people',
                    '/tag/topic1', '/bookmarks', '/notifications', '/messages', '/settings', '/post/1',
                    '/create_post', '/edit_post/1']:
            self.assertEqual(self.client.get(url).status_code, 200, url)
        data = self.client.get('/feed?page=2', headers=JSON).get_json()
        self.assertEqual(data['html'].count('data-post='), 2)
        self.assertIsNone(data['next'])
        self.assertEqual(self.client.get('/u/nobody').status_code, 404)


class InteractionTests(PostfyTestCase):
    def test_reactions_toggle_and_notify(self):
        post_id = self.make_post(self.alice)
        self.login(self.bob)
        data = self.client.post(f'/react/like/{post_id}', headers=JSON).get_json()
        self.assertEqual((data['reaction'], data['like_count']), ('like', 1))
        self.assertEqual(self.count(Notification, user_id=self.alice, kind='like'), 1)
        data = self.client.post(f'/react/dislike/{post_id}', headers=JSON).get_json()
        self.assertEqual((data['like_count'], data['dislike_count']), (0, 1))
        self.assertEqual(self.count(Notification, user_id=self.alice, kind='like'), 0)
        data = self.client.post(f'/react/dislike/{post_id}', headers=JSON).get_json()
        self.assertIsNone(data['reaction'])

    def test_comments_permissions(self):
        post_id = self.make_post(self.alice)
        self.login(self.bob)
        data = self.client.post(f'/add_comment/{post_id}', headers=JSON,
                                data={'comment_content': 'Nice @alice'}).get_json()
        self.assertEqual(data['count'], 1)
        self.assertEqual(self.count(Notification, user_id=self.alice, kind='comment'), 1)
        self.assertEqual(self.count(Notification, user_id=self.alice, kind='mention'), 0)
        with app.app_context():
            comment_id = Comment.query.one().id
        data = self.client.post(f'/edit_comment/{comment_id}', headers=JSON,
                                data={'comment_content': 'Edited'}).get_json()
        self.assertIn('Edited', data['html'])
        # The post owner may delete comments on their post, others may not edit them
        self.login(self.alice)
        r = self.client.post(f'/edit_comment/{comment_id}', headers=JSON, data={'comment_content': 'x'})
        self.assertEqual(r.status_code, 403)
        data = self.client.post(f'/delete_comment/{comment_id}', headers=JSON).get_json()
        self.assertEqual(data['count'], 0)
        self.assertEqual(self.count(Notification, kind='comment'), 0)

    def test_follow_bookmark_and_messages(self):
        post_id = self.make_post(self.bob)
        self.login(self.alice)
        data = self.client.post(f'/follow/{self.bob}', headers=JSON).get_json()
        self.assertEqual((data['following'], data['followers']), (True, 1))
        self.assertEqual(self.client.post(f'/follow/{self.alice}', headers=JSON).status_code, 400)
        self.assertIn('Hello', self.client.get('/feed?tab=following').get_data(as_text=True))
        data = self.client.post(f'/bookmark/{post_id}', headers=JSON).get_json()
        self.assertTrue(data['bookmarked'])
        self.assertIn('Hello', self.client.get('/bookmarks').get_data(as_text=True))

        data = self.client.post('/messages/bob', headers=JSON, data={'body': 'Hi Bob!'}).get_json()
        self.assertTrue(data['ok'])
        bob = app.test_client()
        self.login(self.bob, bob)
        self.assertEqual(bob.get('/api/counts').get_json()['messages'], 1)
        self.assertIn('Hi Bob!', bob.get('/messages/alice').get_data(as_text=True))
        self.assertEqual(bob.get('/api/counts').get_json()['messages'], 0)
        bob.post('/messages/alice', headers=JSON, data={'body': 'Hey!'})
        poll = self.client.get('/api/messages/bob?after=0').get_json()
        self.assertIn('Hey!', poll['html'])
        self.assertGreater(poll['seen_id'], 0)

    def test_notifications_page_marks_read(self):
        post_id = self.make_post(self.alice)
        self.login(self.bob)
        self.client.post(f'/react/like/{post_id}', headers=JSON)
        self.client.post(f'/follow/{self.alice}', headers=JSON)
        self.login(self.alice)
        self.assertEqual(self.client.get('/api/counts').get_json()['notifications'], 2)
        page = self.client.get('/notifications').get_data(as_text=True)
        self.assertIn('liked your post', page)
        self.assertIn('started following you', page)
        self.assertEqual(self.client.get('/api/counts').get_json()['notifications'], 0)


class SettingsTests(PostfyTestCase):
    def test_profile_update_and_username_rules(self):
        self.login(self.alice)
        self.client.post('/settings/profile', data={
            'first_name': 'Alicia', 'last_name': 'S', 'username': 'bob', 'bio': ''})
        with app.app_context():
            self.assertEqual(db.session.get(User, self.alice).username, 'alice')
        self.client.post('/settings/profile', content_type='multipart/form-data', data={
            'first_name': 'Alicia', 'last_name': 'S', 'username': 'alicia', 'bio': 'Hi there',
            'website': 'alicia.dev', 'profile_picture': (io.BytesIO(PNG), 'me.png')})
        with app.app_context():
            user = db.session.get(User, self.alice)
            self.assertEqual((user.username, user.website), ('alicia', 'https://alicia.dev'))
            self.assertNotEqual(user.profile_picture, 'default.jpg')
        self.assertFalse(self.client.get('/api/username-available?username=bob').get_json()['available'])
        self.assertTrue(self.client.get('/api/username-available?username=alicia').get_json()['available'])

    def test_password_change_and_export(self):
        self.login(self.alice)
        self.client.post('/settings/password', data={
            'current_password': 'wrong', 'new_password': 'newpass1', 'confirm_password': 'newpass1'})
        self.assertEqual(app.test_client().post('/login', data={
            'email': 'alice', 'password': 'newpass1'}).status_code, 200)
        self.client.post('/settings/password', data={
            'current_password': 'secret123', 'new_password': 'newpass1', 'confirm_password': 'newpass1'})
        self.assertEqual(app.test_client().post('/login', data={
            'email': 'alice', 'password': 'newpass1'}).status_code, 302)
        export = self.client.get('/settings/export').get_json()
        self.assertEqual(export['profile']['username'], 'alice')

    def test_delete_account_removes_everything(self):
        post_id = self.make_post(self.alice)
        other_post = self.make_post(self.bob)
        self.login(self.bob)
        self.client.post(f'/add_comment/{post_id}', data={'comment_content': 'hi'})
        self.client.post(f'/follow/{self.alice}')
        self.login(self.alice)
        self.client.post(f'/react/like/{other_post}')
        self.client.post(f'/bookmark/{other_post}')
        self.client.post('/messages/bob', data={'body': 'bye'})
        self.client.post('/settings/delete', data={'password': 'wrong'})
        self.assertEqual(self.count(User, id=self.alice), 1)
        self.client.post('/settings/delete', data={'password': 'secret123'})
        self.assertEqual(self.count(User, id=self.alice), 0)
        for model in (Post, Comment, Reaction, Bookmark, Follow, Notification, Message):
            self.assertEqual(self.count(model) if model is not Post else self.count(Post, user_id=self.alice),
                             0, model.__name__)
        self.assertEqual(self.client.get('/feed').status_code, 302)


class AdminTests(PostfyTestCase):
    def test_admin_delete_user_cascades(self):
        from admin import AdminUser
        with app.app_context():
            db.session.add(AdminUser(username='root', email='root@example.com',
                                     password=generate_password_hash('adminpw')))
            db.session.commit()
        post_id = self.make_post(self.alice)
        self.login(self.bob)
        self.client.post(f'/add_comment/{post_id}', data={'comment_content': 'hi'})
        self.client.post(f'/react/like/{post_id}')
        admin = app.test_client()
        admin.post('/admin/login', data={'username': 'root', 'password': 'adminpw'})
        page = admin.get('/admin/').get_data(as_text=True)
        self.assertIn('New Users Today', page)
        admin.post(f'/admin/users/delete/{self.alice}')
        self.assertEqual(self.count(Post), 0)
        self.assertEqual(self.count(Comment), 0)
        self.assertEqual(self.count(Reaction), 0)
        self.assertEqual(self.count(Notification), 0)


class SchemaUpgradeTests(unittest.TestCase):
    def test_old_database_gets_new_columns_and_usernames(self):
        """Start the real app against a database from before this release."""
        path = os.path.join(TMP, 'legacy.db')
        con = sqlite3.connect(path)
        con.executescript("""
            CREATE TABLE user (id INTEGER PRIMARY KEY, first_name VARCHAR(100) NOT NULL,
                last_name VARCHAR(100) NOT NULL, user_id VARCHAR(100) NOT NULL UNIQUE,
                email VARCHAR(120) NOT NULL UNIQUE, password VARCHAR(200) NOT NULL,
                gender VARCHAR(10) NOT NULL, profile_picture VARCHAR(200));
            CREATE TABLE post (id INTEGER PRIMARY KEY, title VARCHAR(255) NOT NULL, content TEXT NOT NULL,
                user_id INTEGER NOT NULL, date_posted DATETIME);
            INSERT INTO user VALUES (1, 'Old', 'Timer', 'old@example.com', 'old@example.com', 'x', 'male', NULL);
            INSERT INTO user VALUES (2, 'Old', 'Twin', 'old@other.com', 'old@other.com', 'x', 'male', NULL);
            INSERT INTO post VALUES (1, 'Legacy', 'Still here', 1, '2025-03-01 10:00:00');
        """)
        con.commit()
        con.close()

        code = ("import app as m\n"
                "with m.app.app_context():\n"
                "    print([u.username for u in m.User.query.order_by(m.User.id)])\n"
                "    print(m.app.test_client().get('/u/old').status_code)\n")
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env = {**os.environ, 'DATABASE_URL': 'sqlite:///' + path, 'PYTHONDONTWRITEBYTECODE': '1'}
        out = subprocess.run([sys.executable, '-c', code], cwd=root, env=env,
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("['old', 'old2']", out.stdout)
        self.assertIn('200', out.stdout)

        con = sqlite3.connect(path)
        user_cols = {row[1] for row in con.execute('PRAGMA table_info(user)')}
        post_cols = {row[1] for row in con.execute('PRAGMA table_info(post)')}
        tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        post = con.execute('SELECT title, content FROM post WHERE id = 1').fetchone()
        con.close()
        self.assertTrue({'username', 'bio', 'cover_picture', 'created_at', 'is_active'} <= user_cols)
        self.assertTrue({'image', 'updated_at'} <= post_cols)
        self.assertTrue({'follow', 'bookmark', 'notification', 'message'} <= tables)
        self.assertEqual(post, ('Legacy', 'Still here'))


if __name__ == '__main__':
    unittest.main()
