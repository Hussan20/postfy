"""Build a static, clickable demo of Postfy for GitHub Pages.

GitHub Pages can only host static files, so this script runs the real Flask
app against a temporary database filled with demo content, renders every page
a visitor can reach, and writes them out as plain HTML. In the browser,
static/js/app.js notices the demo flag and simulates the server, so likes,
comments, follows, posting and messages still work (nothing is saved).

Usage:
    python tools/build_static.py --out _site --base /postfy
Then preview it with:
    python tools/build_static.py --serve
"""
import argparse
import json
import os
import re
import shutil
import sys
import tempfile
from collections import deque
from datetime import datetime
from types import SimpleNamespace
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP_PREFIXES = ('/static/', '/admin', '/api/', '/logout', '/settings/export')
# Uploads are served from these folders; the demo gets its own copies
UPLOAD_DIRS = ('profile_pics', 'cover_pics', 'post_images')


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--out', default=os.path.join(ROOT, '_site'), help='output folder')
    parser.add_argument('--base', default=os.environ.get('PAGES_BASE', '/postfy'),
                        help='URL path the site is served from, e.g. /postfy for user.github.io/postfy')
    parser.add_argument('--site-url', default=os.environ.get('PAGES_SITE_URL', 'https://hussan20.github.io'),
                        help='origin used for absolute links (share / copy link)')
    parser.add_argument('--serve', action='store_true', help='build, then serve the result on localhost:8000')
    return parser.parse_args()


def main():
    args = parse_args()
    base = '/' + args.base.strip('/') if args.base.strip('/') else ''
    out = os.path.abspath(args.out)
    work = tempfile.mkdtemp(prefix='postfy-pages-')

    # Configure the app before it is imported: temporary DB + demo mode
    os.environ['DATABASE_URL'] = 'sqlite:///' + os.path.join(work, 'demo.db')
    os.environ['POSTFY_STATIC_DEMO'] = '1'
    sys.path.insert(0, ROOT)
    import app as postfy
    import demo_data
    from flask import g, url_for

    app, db = postfy.app, postfy.db
    app.config.update(POSTS_PER_PAGE=500, CSRF_ENABLED=False, STATIC_DEMO=True, TESTING=True)
    for key, folder in (('UPLOAD_FOLDER', 'profile_pics'), ('COVER_FOLDER', 'cover_pics'),
                        ('POST_IMAGE_FOLDER', 'post_images')):
        app.config[key] = os.path.join(work, folder)
        os.makedirs(app.config[key], exist_ok=True)

    print(demo_data.seed(db, app))

    with app.app_context():
        demo_user = postfy.User.query.filter_by(email=demo_data.DEMO_EMAIL).one()
        users = postfy.User.query.all()
        posts = postfy.Post.query.all()
        demo_id, demo_handle = demo_user.id, demo_user.handle
        handles = [u.handle for u in users]
        post_ids = [p.id for p in posts]
        my_posts = [p.id for p in posts if p.user_id == demo_id]
        # Snapshot read-state so crawling doesn't mark everything as read
        notif_read = {n.id: n.is_read for n in postfy.Notification.query}
        msg_read = {m.id: m.is_read for m in postfy.Message.query}

    def restore_read_state():
        for model, state in ((postfy.Notification, notif_read), (postfy.Message, msg_read)):
            for flag in (True, False):
                ids = [i for i, v in state.items() if v is flag]
                if ids:
                    model.query.filter(model.id.in_(ids)).update({'is_read': flag}, synchronize_session=False)
        db.session.commit()

    index_cache = {}

    @app.context_processor
    def demo_samples():
        """Objects the demo templates clone to show new posts/comments/messages."""
        if 'index' not in index_cache:
            index_cache['index'] = {
                'users': [postfy.user_json(u) | {'bio': u.bio or ''} for u in postfy.User.query.all()],
                'tags': [{'name': t, 'count': n, 'url': url_for('tag', name=t)} for t, n in postfy.trending_tags(50)],
            }
        samples = SimpleNamespace(index=index_cache['index'])
        user = g.get('user')
        if user:
            now = datetime.utcnow()
            samples.post = SimpleNamespace(
                id=999999, user=user, user_id=user.id, title='', content='', date_posted=now,
                updated_at=None, is_edited=False, image=None, image_url=None, like_count=0,
                dislike_count=0, my_reaction=None, is_bookmarked=False, comment_list=[], comment_count=0)
            samples.comment = SimpleNamespace(id=999999, user=user, user_id=user.id, content='',
                                              date_created=now, post_id=999999)
            samples.message = SimpleNamespace(id=999999, sender_id=user.id, body='', created_at=now)
        return {'demo_samples': samples}

    base_url = args.site_url.rstrip('/') + base
    guest = app.test_client()
    member = app.test_client()
    with member.session_transaction(base_url=base_url) as sess:
        sess['user_id'] = demo_id

    def normalize(url):
        """Drop the base path and query parameters that don't change the page."""
        parts = urlsplit(url.replace('&amp;', '&'))
        path = parts.path[len(base):] if base and parts.path.startswith(base) else parts.path
        query = [(k, v) for k, v in parse_qsl(parts.query) if k not in ('next', 'page')]
        return (path or '/') + ('?' + urlencode(query) if query else '')

    def output_rel(page):
        """/u/nour?tab=likes -> u/nour/q-tab-likes/index.html"""
        parts = urlsplit(page)
        segs = [unquote(s) for s in parts.path.split('/') if s]
        if parts.query:
            segs.append('q-' + re.sub(r'[^\w-]+', '-', unquote(parts.query)).strip('-'))
        if segs and '.' in segs[-1] and not parts.query:
            return '/'.join(segs), True
        return '/'.join(segs + ['index.html']), False

    def public_url(page):
        rel, is_file = output_rel(page)
        if is_file:
            return base + '/' + quote(rel)
        folder = rel[:-len('index.html')]
        return base + '/' + quote(folder)

    pages, redirects = {}, {}
    queue, queued = deque(), set()
    guest_pages = {'/', '/login', '/signup'}

    def enqueue(page):
        page = normalize(page)
        if page in queued or page.startswith(SKIP_PREFIXES) or '__' in page or '999999' in page:
            return
        queued.add(page)
        queue.append(page)

    for page in ['/', '/login', '/signup', '/feed', '/people', '/bookmarks', '/settings', '/search',
                 '/messages', '/profile', '/create_post', '/notifications', '/manifest.webmanifest']:
        enqueue(page)
    for h in handles:
        for page in (f'/u/{h}', f'/u/{h}/followers', f'/u/{h}/following'):
            enqueue(page)
        if h != demo_handle:
            enqueue(f'/messages/{h}')
    for pid in post_ids:
        enqueue(f'/post/{pid}')
    for pid in my_posts:
        enqueue(f'/edit_post/{pid}')

    # Any URL under the base path (used for rewriting) / only real links (used for crawling)
    link_re = re.compile(re.escape(base) + r'/[^"\'\s<>()]*' if base else r'(?<=["\'])/[^"\'\s<>()]*')
    href_re = re.compile(r'href="(' + re.escape(base) + r'/[^"#]*)')

    with app.app_context():
        while queue:
            page = queue.popleft()
            client = guest if page in guest_pages else member
            response = client.get(page, base_url=base_url)
            restore_read_state()
            if response.status_code in (301, 302):
                redirects[page] = normalize(response.headers['Location'])
                enqueue(redirects[page])
                continue
            if response.status_code != 200:
                print(f'  ! {response.status_code} {page}')
                continue
            body = response.get_data(as_text=True)
            pages[page] = body
            if response.mimetype == 'text/html':
                for match in href_re.findall(body):
                    enqueue(match)

        not_found = guest.get('/this-page-does-not-exist', base_url=base_url).get_data(as_text=True)

    # Rewrite links to the static URLs (feed -> feed/, ?tab=x -> q-tab-x/)
    mapping = {p: public_url(p) for p in pages}
    mapping.update({p: public_url(t) for p, t in redirects.items() if t in pages})

    def rewrite(html):
        def swap(m):
            raw = m.group(0)
            url, _, fragment = raw.partition('#')
            target = mapping.get(normalize(url))
            if not target:
                return raw
            return target + ('#' + fragment if fragment else '')
        return link_re.sub(swap, html)

    if os.path.exists(out):
        shutil.rmtree(out)
    os.makedirs(out)
    for page, body in pages.items():
        rel, _ = output_rel(page)
        path = os.path.join(out, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(rewrite(body))
    for page, target in redirects.items():
        if target not in pages:
            continue
        rel, _ = output_rel(page)
        path = os.path.join(out, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(f'<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0; url={mapping[page]}">'
                    f'<link rel="canonical" href="{mapping[page]}"><title>Redirecting…</title>'
                    f'<a href="{mapping[page]}">Continue</a>')
    with open(os.path.join(out, '404.html'), 'w', encoding='utf-8') as f:
        f.write(rewrite(not_found))
    open(os.path.join(out, '.nojekyll'), 'w').close()

    # Static assets (without anyone's uploaded photos) + the demo's own uploads
    shutil.copytree(os.path.join(ROOT, 'static'), os.path.join(out, 'static'),
                    ignore=shutil.ignore_patterns(*UPLOAD_DIRS, 'settings', 'logo1.png'))
    for folder in UPLOAD_DIRS:
        shutil.copytree(os.path.join(work, folder), os.path.join(out, 'static', folder), dirs_exist_ok=True)

    shutil.rmtree(work, ignore_errors=True)
    total = sum(len(files) for _, _, files in os.walk(out))
    print(f'Built {len(pages)} pages ({len(redirects)} redirects, {total} files) into {out}')
    print(f'Entry point: {args.site_url.rstrip("/")}{base}/')

    if args.serve:
        serve(out, base)


def serve(out, base):
    """Serve the build at http://127.0.0.1:8000<base>/ like GitHub Pages would."""
    import http.server

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=out, **kwargs)

        def translate_path(self, path):
            if base and path.startswith(base):
                path = path[len(base):] or '/'
            return super().translate_path(path)

    with http.server.ThreadingHTTPServer(('127.0.0.1', 8000), Handler) as httpd:
        print(f'Serving on http://127.0.0.1:8000{base}/  (Ctrl+C to stop)')
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == '__main__':
    main()
