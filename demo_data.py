"""Demo content for local development and the GitHub Pages preview.

Run `flask --app app seed-demo` to load it into your database. Sign in with
demo@postfy.dev / postfy123 afterwards.
"""
import os
import random
from datetime import datetime, timedelta

from werkzeug.security import generate_password_hash

DEMO_EMAIL = 'demo@postfy.dev'
DEMO_PASSWORD = 'postfy123'

USERS = [
    # username, first, last, gender, bio, location, website, cover
    ('nour', 'Nour', 'Kareem', 'female',
     'Front-end developer ✦ typography nerd ✦ powered by coffee. Building delightful things on the web.',
     'Baghdad, Iraq', 'https://postfy.dev', 'aurora'),
    ('omar', 'Omar', 'Haddad', 'male',
     'Full-stack engineer. Python, Flask and too many side projects. #webdev',
     'Amman, Jordan', 'https://github.com', 'dusk'),
    ('lina', 'Lina', 'Farouk', 'female',
     'Street & landscape photographer 📷 Chasing golden hour everywhere.',
     'Beirut, Lebanon', '', 'sunset'),
    ('maya', 'Maya', 'Chen', 'female',
     'Product designer. I care about focus rings, empty states and good defaults.',
     'Toronto, Canada', 'https://dribbble.com', 'aurora'),
    ('yusuf', 'Yusuf', 'Ali', 'male',
     'Runner, hiker, early riser. Trying to spend more time outside than online.',
     'Erbil, Iraq', '', 'ocean'),
    ('zara', 'Zara', 'Ahmed', 'female',
     'Career switcher learning to code 👩‍💻 Documenting the journey.',
     'Baghdad, Iraq', '', None),
    ('leo', 'Leo', 'Martins', 'male',
     'Travel writer. Currently somewhere with bad Wi-Fi and great views.',
     'Lisbon, Portugal', '', 'ocean'),
    ('samr', 'Sam', 'Rivera', 'other',
     'Reading, writing and building calm productivity systems.',
     'Austin, USA', '', None),
]

POSTS = [
    # key, author, hours ago, title, content, image
    ('sunset', 'lina', 0.4, 'Golden hour from the rooftop 🌅',
     'Caught the last light over the city tonight. Some evenings just remind you to slow down.'
     ' #photography #sunset', 'sunset'),
    ('darkmode', 'omar', 1.6, 'Shipped dark mode today!',
     'After three weeks of tweaking color tokens, our app finally has a proper dark theme. '
     'Biggest lesson: design with semantic tokens from day one, not hex codes. #webdev #design'
     '\n\nShoutout to @maya for the palette review 🙏', None),
    ('details', 'maya', 3.2, 'Small UI details that make a big difference',
     '1. Focus rings you can actually see\n2. Buttons that show a loading state\n'
     '3. Empty states that tell you what to do next\n4. Relative timestamps with the full date on hover\n\n'
     'What would you add? #design #ux', None),
    ('run', 'yusuf', 5.5, 'Morning run: new 10K personal best 🏃',
     'Finally broke 45 minutes! Consistency beats intensity every single time. #fitness #running',
     None),
    ('baghdad', 'zara', 8, 'صباح الخير من بغداد ☀️',
     'بداية يوم جديد مع فنجان قهوة وأفكار جديدة. شاركوني ما هي خططكم لهذا الأسبوع؟ #بغداد #قهوة',
     None),
    ('ocean', 'leo', 12, 'The ocean was unreal today',
     'Spent the afternoon at the coast. No signal, no notifications, just waves. Highly recommend. '
     '#travel #nature', 'waves'),
    ('hello', 'nour', 20, 'Hello Postfy! 👋',
     "Just joined and already loving the vibe here. I'm a front-end developer who's into typography, "
     'coffee and long walks. Say hi! #introductions', None),
    ('books', 'samr', 26, 'Book recommendation: Atomic Habits',
     "Re-reading this one and it hits different the second time. Tiny changes, remarkable results. "
     "What's on your reading list? #books", None),
    ('python', 'omar', 31, 'Python tip of the day 🐍',
     'Use enumerate() instead of range(len(items)) — cleaner and less error-prone:\n\n'
     'for i, item in enumerate(items):\n    print(i, item)\n\n#python #webdev', None),
    ('neon', 'lina', 40, 'Neon nights',
     'Downtown after the rain. Every surface turns into a mirror. #photography #city', 'city'),
    ('palette', 'maya', 52, 'Color palette exploration',
     'Playing with gradients for a new brand concept — electric blue into magenta. Thoughts? #design',
     'blobs'),
    ('hike', 'yusuf', 70, 'Weekend hike plans?',
     'Looking for trail recommendations within two hours of the city. Bonus points for waterfalls 🌊 '
     '#nature #hiking', None),
    ('learning', 'zara', 92, 'Learning to code at 30',
     "Six months in and I just built my first full-stack app with Flask! It's never too late to start. "
     '#python #learning', None),
    ('setup', 'samr', 115, 'My productivity setup for 2026',
     'Paper notebook for planning, one app for tasks, notifications off until noon. Simple wins. '
     '#productivity', None),
]

COMMENTS = [
    # post key, author, minutes after post, content
    ('sunset', 'maya', 12, 'Those colors are unreal 😍'),
    ('sunset', 'nour', 20, 'Wallpaper material. Which camera?'),
    ('sunset', 'lina', 25, '@nour just my phone this time! Good light does all the work.'),
    ('darkmode', 'maya', 30, 'Looks fantastic — the contrast on the muted text is spot on.'),
    ('darkmode', 'nour', 45, 'Semantic tokens FTW. Did you support a system preference too?'),
    ('darkmode', 'omar', 50, '@nour yes! Light, dark and "follow system".'),
    ('details', 'omar', 20, 'Keyboard shortcuts for power users!'),
    ('details', 'zara', 35, 'Toasts that don\'t block the UI 🙌'),
    ('details', 'nour', 60, 'Skeleton loaders instead of spinners.'),
    ('run', 'leo', 40, 'Huge! Congrats 🎉'),
    ('baghdad', 'nour', 15, 'صباح النور! ☕'),
    ('ocean', 'lina', 90, 'Adding this to my list.'),
    ('hello', 'maya', 30, 'Welcome, Nour! Great to have you here.'),
    ('hello', 'omar', 55, 'Welcome aboard 🚀'),
    ('hello', 'samr', 80, 'Hi @nour! Loved your typography thread.'),
    ('books', 'zara', 60, 'Deep Work by Cal Newport is next on mine.'),
    ('python', 'zara', 45, 'Saving this one, thanks!'),
    ('learning', 'omar', 120, 'Amazing progress — keep going!'),
]

FOLLOWS = {
    'nour': ['omar', 'lina', 'maya', 'zara'],
    'omar': ['nour', 'maya', 'zara', 'samr'],
    'lina': ['nour', 'leo', 'maya'],
    'maya': ['nour', 'omar', 'lina'],
    'yusuf': ['leo', 'lina', 'nour'],
    'zara': ['nour', 'omar', 'maya'],
    'leo': ['lina', 'yusuf', 'nour'],
    'samr': ['maya', 'omar'],
}

BOOKMARKS = ['details', 'python', 'palette']

MESSAGES = [
    # sender, recipient, minutes ago, body, read
    ('omar', 'nour', 190, 'Hey Nour! Saw your intro post — welcome 👋', True),
    ('nour', 'omar', 185, 'Thanks Omar! Your dark mode write-up was great.', True),
    ('omar', 'nour', 170, 'Glad it helped. Want to pair on the design tokens for my side project?', True),
    ('nour', 'omar', 160, 'Absolutely, I love that stuff. Tomorrow evening?', True),
    ('omar', 'nour', 12, 'Perfect — I will send you the repo link tonight 🚀', False),
    ('lina', 'nour', 400, 'Your comment made my day, thank you!', True),
    ('nour', 'lina', 395, 'Your photos are stunning. Do you sell prints?', True),
    ('lina', 'nour', 380, 'Not yet, but maybe soon 😊', True),
    ('maya', 'nour', 45, 'Quick question about your font pairing on the landing page…', False),
]

ART = {
    'sunset': """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 750">
<defs><linearGradient id="s" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#2b1055"/>
<stop offset=".45" stop-color="#d53369"/><stop offset=".8" stop-color="#ffb347"/></linearGradient>
<radialGradient id="sun"><stop offset="0" stop-color="#fff3b0"/><stop offset="1" stop-color="#ff9a3c"/></radialGradient></defs>
<rect width="1200" height="750" fill="url(#s)"/><circle cx="600" cy="470" r="150" fill="url(#sun)" opacity=".95"/>
<path d="M0 520 L180 380 L330 480 L520 330 L700 470 L880 350 L1050 460 L1200 390 V750 H0Z" fill="#3a1650" opacity=".85"/>
<path d="M0 600 L220 480 L420 590 L640 470 L860 600 L1040 520 L1200 580 V750 H0Z" fill="#1d0b30"/>
<g fill="#1d0b30"><rect x="140" y="560" width="40" height="190"/><rect x="200" y="520" width="60" height="230"/>
<rect x="950" y="540" width="50" height="210"/><rect x="1010" y="500" width="70" height="250"/></g></svg>""",
    'waves': """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 750">
<defs><linearGradient id="sky" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#89f7fe"/><stop offset="1" stop-color="#66a6ff"/></linearGradient></defs>
<rect width="1200" height="750" fill="url(#sky)"/><circle cx="920" cy="170" r="70" fill="#fffbe6" opacity=".9"/>
<path d="M0 360 Q150 320 300 360 T600 360 T900 360 T1200 360 V750 H0Z" fill="#3a7bd5" opacity=".7"/>
<path d="M0 440 Q150 400 300 440 T600 440 T900 440 T1200 440 V750 H0Z" fill="#1e5aa8" opacity=".85"/>
<path d="M0 530 Q150 490 300 530 T600 530 T900 530 T1200 530 V750 H0Z" fill="#0f3d7a"/>
<path d="M0 620 Q150 585 300 620 T600 620 T900 620 T1200 620 V750 H0Z" fill="#f2d7a6"/></svg>""",
    'city': """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 750">
<defs><linearGradient id="n" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#0f0c29"/><stop offset=".6" stop-color="#302b63"/><stop offset="1" stop-color="#24243e"/></linearGradient>
<linearGradient id="r" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ff57ff" stop-opacity=".45"/><stop offset="1" stop-color="#00b8f4" stop-opacity="0"/></linearGradient></defs>
<rect width="1200" height="750" fill="url(#n)"/>
<g fill="#16132e"><rect x="40" y="220" width="130" height="330"/><rect x="190" y="140" width="110" height="410"/><rect x="320" y="260" width="150" height="290"/>
<rect x="490" y="90" width="120" height="460"/><rect x="630" y="200" width="140" height="350"/><rect x="790" y="120" width="100" height="430"/>
<rect x="910" y="240" width="150" height="310"/><rect x="1080" y="170" width="100" height="380"/></g>
<g fill="#00b8f4" opacity=".85"><rect x="210" y="170" width="16" height="10"/><rect x="250" y="210" width="16" height="10"/><rect x="520" y="130" width="16" height="10"/>
<rect x="560" y="190" width="16" height="10"/><rect x="820" y="160" width="16" height="10"/><rect x="940" y="280" width="16" height="10"/></g>
<g fill="#ff57ff" opacity=".85"><rect x="360" y="300" width="16" height="10"/><rect x="660" y="240" width="16" height="10"/><rect x="1110" y="210" width="16" height="10"/>
<rect x="80" y="260" width="16" height="10"/><rect x="700" y="330" width="16" height="10"/></g>
<rect y="550" width="1200" height="200" fill="#0b0a1f"/><rect y="550" width="1200" height="200" fill="url(#r)"/></svg>""",
    'blobs': """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 750">
<defs><filter id="b" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="60"/></filter></defs>
<rect width="1200" height="750" fill="#0d0a1c"/><g filter="url(#b)"><circle cx="360" cy="330" r="230" fill="#00b8f4"/>
<circle cx="760" cy="420" r="260" fill="#9a00f7"/><circle cx="930" cy="230" r="170" fill="#ff57ff"/><circle cx="520" cy="600" r="150" fill="#00ff87" opacity=".6"/></g></svg>""",
}

COVERS = {
    'aurora': ('#00b8f4', '#9a00f7', '#ff57ff'),
    'dusk': ('#232526', '#414345', '#9a00f7'),
    'sunset': ('#ff512f', '#dd2476', '#6a11cb'),
    'ocean': ('#2193b0', '#6dd5ed', '#1e3c72'),
}


def cover_svg(colors):
    a, b, c = colors
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1500 500">
<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="{a}"/><stop offset=".55" stop-color="{b}"/><stop offset="1" stop-color="{c}"/></linearGradient>
<filter id="f"><feGaussianBlur stdDeviation="40"/></filter></defs>
<rect width="1500" height="500" fill="url(#g)"/><g filter="url(#f)" opacity=".55"><circle cx="300" cy="120" r="180" fill="#fff" opacity=".35"/>
<circle cx="1200" cy="420" r="220" fill="{a}"/></g></svg>"""


def _write(folder, name, content):
    path = os.path.join(folder, name)
    if not os.path.exists(path):
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
    return name


def seed(db, app):
    import app as postfy
    User, Post, Comment, Reaction = postfy.User, postfy.Post, postfy.Comment, postfy.Reaction
    Follow, Bookmark, Notification, Message = postfy.Follow, postfy.Bookmark, \
        postfy.Notification, postfy.Message

    with app.app_context():
        if User.query.filter_by(email=DEMO_EMAIL).first():
            return 'already seeded'

        rng = random.Random(42)
        now = datetime.utcnow()
        users = {}
        for i, (username, first, last, gender, bio, location, website, cover) in enumerate(USERS):
            if User.query.filter_by(username=username).first():
                username = postfy.generate_username(username)
            email = DEMO_EMAIL if i == 0 else f'{username}@postfy.dev'
            cover_file = _write(app.config['COVER_FOLDER'], f'demo-{cover}.svg',
                                cover_svg(COVERS[cover])) if cover else None
            user = User(first_name=first, last_name=last, user_id=email, email=email,
                        username=username, password=generate_password_hash(DEMO_PASSWORD),
                        gender=gender, bio=bio, location=location, website=website or None,
                        cover_picture=cover_file, profile_picture='default.jpg',
                        created_at=now - timedelta(days=30 + i * 11))
            db.session.add(user)
            users[USERS[i][0]] = user
        db.session.flush()

        posts = {}
        for key, author, hours, title, content, image in POSTS:
            image_file = _write(app.config['POST_IMAGE_FOLDER'], f'demo-{image}.svg',
                                ART[image]) if image else None
            post = Post(title=title, content=content, user_id=users[author].id, image=image_file,
                        date_posted=now - timedelta(hours=hours))
            db.session.add(post)
            posts[key] = post
        db.session.flush()

        comments = []
        for key, author, minutes, content in COMMENTS:
            post = posts[key]
            comment = Comment(content=content, post_id=post.id, user_id=users[author].id,
                              date_created=post.date_posted + timedelta(minutes=minutes))
            db.session.add(comment)
            comments.append((comment, post, users[author]))
        db.session.flush()

        people = list(users.values())
        for key, post in posts.items():
            likers = rng.sample(people, rng.randint(2, len(people)))
            for user in likers:
                if user.id == users['nour'].id and key in ('darkmode', 'details'):
                    continue
                kind = 'dislike' if rng.random() < 0.08 else 'like'
                db.session.add(Reaction(post_id=post.id, user_id=user.id, reaction_type=kind,
                                        created_at=post.date_posted + timedelta(minutes=rng.randint(5, 300))))
                if kind == 'like' and post.user_id == users['nour'].id and user.id != post.user_id:
                    db.session.add(Notification(user_id=post.user_id, actor_id=user.id, kind='like',
                                                post_id=post.id, is_read=rng.random() < 0.5,
                                                created_at=post.date_posted + timedelta(minutes=rng.randint(5, 300))))

        for follower, followed in FOLLOWS.items():
            for name in followed:
                db.session.add(Follow(follower_id=users[follower].id, followed_id=users[name].id,
                                      created_at=now - timedelta(days=rng.randint(1, 20))))
                if name == 'nour':
                    db.session.add(Notification(user_id=users['nour'].id, actor_id=users[follower].id,
                                                kind='follow', is_read=follower not in ('leo', 'yusuf'),
                                                created_at=now - timedelta(hours=rng.randint(2, 60))))

        for comment, post, author in comments:
            if post.user_id == users['nour'].id and author.id != post.user_id:
                db.session.add(Notification(user_id=post.user_id, actor_id=author.id, kind='comment',
                                            post_id=post.id, comment_id=comment.id,
                                            is_read=False, created_at=comment.date_created))
            elif '@nour' in comment.content and post.user_id != users['nour'].id:
                db.session.add(Notification(user_id=users['nour'].id, actor_id=author.id,
                                            kind='mention', post_id=post.id, comment_id=comment.id,
                                            is_read=False, created_at=comment.date_created))

        for key in BOOKMARKS:
            db.session.add(Bookmark(user_id=users['nour'].id, post_id=posts[key].id))

        for sender, recipient, minutes, body, read in MESSAGES:
            db.session.add(Message(sender_id=users[sender].id, recipient_id=users[recipient].id,
                                   body=body, is_read=read, created_at=now - timedelta(minutes=minutes)))

        db.session.commit()
        return f'{len(users)} users, {len(posts)} posts, {len(comments)} comments ' \
               f'(sign in with {DEMO_EMAIL} / {DEMO_PASSWORD})'
