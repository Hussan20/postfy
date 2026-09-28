/* Postfy front-end
 * Progressive enhancement: every feature works without JavaScript through
 * regular links and forms; this file makes them instant and delightful.
 */
(() => {
    'use strict';

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    const $ = (sel, root = document) => root.querySelector(sel);
    const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
    const CONFIG = JSON.parse($('#postfy-config')?.textContent || '{}');
    const URLS = CONFIG.urls || {};
    const DEMO = !!CONFIG.demo;
    const SPRITE = ($('use')?.getAttribute('href') || '').split('#')[0];
    const MAX_UPLOAD = 16 * 1024 * 1024;
    const IMAGE_TYPES = ['image/png', 'image/jpeg', 'image/gif', 'image/webp'];
    const isTyping = (el) => el && (el.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName));
    const reducedMotion = () => document.documentElement.dataset.motion === 'reduced' ||
        (matchMedia('(prefers-reduced-motion: reduce)').matches && document.documentElement.dataset.motion !== 'full');
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const escapeHTML = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    const icon = (name, cls = '') => `<svg class="icon ${cls}" aria-hidden="true"><use href="${SPRITE}#${name}"></use></svg>`;
    const userUrl = (handle) => (URLS.user || '/u/__USER__').replace('__USER__', encodeURIComponent(handle));
    const tagUrl = (tag) => (URLS.tag || '/tag/__TAG__').replace('__TAG__', encodeURIComponent(tag.toLowerCase()));

    const store = {
        get(key, fallback = null) {
            try { const v = localStorage.getItem(key); return v === null ? fallback : JSON.parse(v); } catch { return fallback; }
        },
        set(key, value) { try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* storage unavailable */ } },
        remove(key) { try { localStorage.removeItem(key); } catch { /* storage unavailable */ } },
    };

    function debounce(fn, ms) {
        let t;
        return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
    }

    function compact(n) {
        n = Number(n) || 0;
        if (n < 1000) return String(n);
        if (n < 1e6) return (n / 1000).toFixed(1).replace(/\.0$/, '') + 'K';
        return (n / 1e6).toFixed(1).replace(/\.0$/, '') + 'M';
    }

    function htmlToElement(html) {
        const tpl = document.createElement('template');
        tpl.innerHTML = html.trim();
        return tpl.content;
    }

    // Built at runtime so browsers without regex lookbehind still parse this file
    const RICH_RE = (() => {
        try {
            return new RegExp(String.raw`(https?:\/\/[^\s<>"']+)|(?<![\p{L}\p{N}_#&])#([\p{L}\p{N}_]*\p{L}[\p{L}\p{N}_]*)|(?<![\p{L}\p{N}_@])@([A-Za-z0-9_]{3,30})`, 'gu');
        } catch {
            return /(https?:\/\/[^\s<>"']+)|#([A-Za-z0-9_]*[A-Za-z][A-Za-z0-9_]*)|@([A-Za-z0-9_]{3,30})/g;
        }
    })();

    /** Client-side mirror of the server's `rich` filter (used for demo previews). */
    function richText(text) {
        const re = new RegExp(RICH_RE.source, RICH_RE.flags);
        let out = '', pos = 0, m;
        while ((m = re.exec(text))) {
            out += escapeHTML(text.slice(pos, m.index));
            if (m[1]) {
                let url = m[1], trail = '';
                while (/[.,;:!?)\]}'"]$/.test(url)) { trail = url.slice(-1) + trail; url = url.slice(0, -1); }
                out += `<a href="${escapeHTML(url)}" class="rich-link" target="_blank" rel="noopener nofollow ugc">${escapeHTML(url.replace(/^https?:\/\//, ''))}</a>${escapeHTML(trail)}`;
            } else if (m[2]) {
                out += `<a href="${tagUrl(m[2])}" class="rich-tag">#${escapeHTML(m[2])}</a>`;
            } else {
                out += `<a href="${userUrl(m[3].toLowerCase())}" class="rich-mention">@${escapeHTML(m[3])}</a>`;
            }
            pos = m.index + m[0].length;
        }
        return (out + escapeHTML(text.slice(pos))).replace(/\r?\n/g, '<br>');
    }

    // ---------------------------------------------------------------------
    // Toasts
    // ---------------------------------------------------------------------

    const TOAST_ICONS = { success: 'check-circle', danger: 'alert-circle', warning: 'alert-triangle', info: 'info' };

    function dismissToast(el) {
        if (!el || el.classList.contains('is-leaving')) return;
        el.classList.add('is-leaving');
        setTimeout(() => el.remove(), reducedMotion() ? 0 : 260);
    }

    function armToast(el, duration = 4500) {
        el.style.setProperty('--toast-duration', `${duration}ms`);
        const bar = $('.toast__progress', el);
        if (reducedMotion() || !bar) {
            let remaining = duration, started = Date.now(), timer = setTimeout(() => dismissToast(el), remaining);
            el.addEventListener('mouseenter', () => { clearTimeout(timer); remaining -= Date.now() - started; });
            el.addEventListener('mouseleave', () => { started = Date.now(); timer = setTimeout(() => dismissToast(el), remaining); });
        } else {
            bar.addEventListener('animationend', () => dismissToast(el));
        }
    }

    function toast(message, type = 'info', duration = 4500) {
        const region = $('#toasts');
        if (!region || !message) return;
        const el = document.createElement('div');
        el.className = `toast toast--${type}`;
        el.setAttribute('role', type === 'danger' ? 'alert' : 'status');
        el.innerHTML = `<span class="toast__icon">${icon(TOAST_ICONS[type] || 'info')}</span><p class="toast__msg"></p>` +
            `<button type="button" class="icon-btn icon-btn--sm toast__close" data-toast-close aria-label="Dismiss">${icon('x')}</button>` +
            '<span class="toast__progress"></span>';
        $('.toast__msg', el).textContent = message;
        region.appendChild(el);
        while (region.children.length > 4) dismissToast(region.firstElementChild);
        armToast(el, duration);
    }

    function toastAfterNavigation(message, type = 'success') {
        try { sessionStorage.setItem('postfy:toast', JSON.stringify({ message, type })); } catch { /* ignore */ }
    }

    function initToasts() {
        $$('[data-toast]').forEach((el, i) => armToast(el, 4500 + i * 600));
        try {
            const pending = JSON.parse(sessionStorage.getItem('postfy:toast') || 'null');
            if (pending) { sessionStorage.removeItem('postfy:toast'); toast(pending.message, pending.type); }
        } catch { /* ignore */ }
        document.addEventListener('click', (e) => {
            const btn = e.target.closest('[data-toast-close]');
            if (btn) dismissToast(btn.closest('.toast'));
        });
        window.addEventListener('offline', () => toast("You're offline. We'll reconnect automatically.", 'warning'));
        window.addEventListener('online', () => toast('Back online!', 'success', 2500));
    }

    // ---------------------------------------------------------------------
    // Networking
    // ---------------------------------------------------------------------

    async function request(url, { method = 'POST', body = null, form = null } = {}) {
        if (DEMO) return method === 'GET' ? Demo.get(url) : Demo.post(url, body, form);
        const headers = { 'X-Requested-With': 'XMLHttpRequest', Accept: 'application/json' };
        if (method !== 'GET') headers['X-CSRFToken'] = $('meta[name="csrf-token"]')?.content || '';
        let res;
        try {
            res = await fetch(url, { method, headers, body, credentials: 'same-origin' });
        } catch {
            throw new Error("Couldn't reach Postfy. Check your connection and try again.");
        }
        let data = {};
        try { data = await res.json(); } catch { /* not JSON */ }
        if (res.status === 401 && data.login_url) {
            location.href = `${data.login_url}?next=${encodeURIComponent(location.pathname)}`;
            throw new Error(data.error);
        }
        if (!res.ok) throw new Error(data.error || `Something went wrong (${res.status}). Please try again.`);
        return data;
    }

    const getJSON = (url) => request(url, { method: 'GET' });

    function withQuery(url, params) {
        const u = new URL(url, location.href);
        Object.entries(params).forEach(([k, v]) => u.searchParams.set(k, v));
        return u.pathname + u.search;
    }

    // ---------------------------------------------------------------------
    // Appearance (theme, accent, text size, motion)
    // ---------------------------------------------------------------------

    const Appearance = {
        key: 'postfy:appearance',
        get() {
            const saved = store.get(this.key, {}) || {};
            if (!saved.theme) {
                try { saved.theme = localStorage.getItem('theme') || 'system'; } catch { saved.theme = 'system'; }
            }
            return saved;
        },
        set(patch) {
            const next = { ...this.get(), ...patch };
            store.set(this.key, next);
            try { localStorage.setItem('theme', next.theme); } catch { /* ignore */ }
            this.apply(next);
        },
        resolvedTheme(theme) {
            if (theme === 'light' || theme === 'dark') return theme;
            return matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
        },
        apply(s = this.get()) {
            const root = document.documentElement;
            const theme = this.resolvedTheme(s.theme);
            root.dataset.theme = theme;
            s.accent && s.accent !== 'neon' ? root.dataset.accent = s.accent : delete root.dataset.accent;
            s.fontSize && s.fontSize !== 'default' ? root.dataset.fontSize = s.fontSize : delete root.dataset.fontSize;
            s.motion ? root.dataset.motion = s.motion : delete root.dataset.motion;
            const meta = $('meta[name="theme-color"]');
            if (meta) meta.content = theme === 'light' ? '#f3f5fa' : '#0b0d12';
        },
        toggle() {
            const current = document.documentElement.dataset.theme === 'light' ? 'light' : 'dark';
            this.set({ theme: current === 'light' ? 'dark' : 'light' });
            this.syncControls();
        },
        syncControls() {
            const s = this.get();
            $$('[data-pref]').forEach((input) => {
                const pref = input.dataset.pref;
                if (input.type === 'checkbox') input.checked = s[pref] === input.value;
                else input.checked = (s[pref] || { theme: 'system', accent: 'neon', fontSize: 'default' }[pref]) === input.value;
            });
        },
        init() {
            this.apply();
            matchMedia('(prefers-color-scheme: light)').addEventListener('change', () => {
                if (this.get().theme === 'system') this.apply();
            });
            document.addEventListener('click', (e) => {
                if (e.target.closest('[data-theme-toggle]')) this.toggle();
            });
            $$('[data-pref]').forEach((input) => input.addEventListener('change', () => {
                const pref = input.dataset.pref;
                this.set({ [pref]: input.type === 'checkbox' ? (input.checked ? input.value : '') : input.value });
            }));
            this.syncControls();
        },
    };

    // ---------------------------------------------------------------------
    // Dropdowns, dialogs & confirmations
    // ---------------------------------------------------------------------

    function closeDropdowns(except) {
        $$('[data-dropdown].is-open').forEach((dd) => {
            if (dd === except) return;
            dd.classList.remove('is-open');
            $('[data-dropdown-toggle]', dd)?.setAttribute('aria-expanded', 'false');
        });
    }

    function initDropdowns() {
        document.addEventListener('click', (e) => {
            const toggle = e.target.closest('[data-dropdown-toggle]');
            if (toggle) {
                const dd = toggle.closest('[data-dropdown]');
                const open = !dd.classList.contains('is-open');
                closeDropdowns(dd);
                dd.classList.toggle('is-open', open);
                toggle.setAttribute('aria-expanded', String(open));
                if (open) $('.dropdown__item', dd)?.focus({ preventScroll: true });
                return;
            }
            if (e.target.closest('.dropdown__item')) { setTimeout(() => closeDropdowns(), 0); return; }
            if (!e.target.closest('[data-dropdown]')) closeDropdowns();
        });
        document.addEventListener('keydown', (e) => {
            const menu = e.target.closest('.dropdown__menu');
            if (!menu || !['ArrowDown', 'ArrowUp'].includes(e.key)) return;
            e.preventDefault();
            const items = $$('.dropdown__item', menu);
            const i = items.indexOf(document.activeElement);
            items[(i + (e.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length]?.focus();
        });
    }

    function openDialog(id) {
        const dialog = document.getElementById(id);
        if (!dialog || dialog.open) return dialog;
        closeDropdowns();
        dialog.showModal();
        return dialog;
    }

    function initDialogs() {
        document.addEventListener('click', (e) => {
            const opener = e.target.closest('[data-open-dialog]');
            if (opener) {
                const id = opener.dataset.openDialog;
                if (id === 'report-dialog') resetReportDialog();
                const dialog = openDialog(id);
                $('input:not([type=hidden]), textarea', dialog)?.focus();
                return;
            }
            const closer = e.target.closest('[data-close-dialog]');
            if (closer) { closer.closest('dialog')?.close(); return; }
            if (e.target.tagName === 'DIALOG') {
                const r = e.target.getBoundingClientRect();
                const inside = e.clientX >= r.left && e.clientX <= r.right && e.clientY >= r.top && e.clientY <= r.bottom;
                if (!inside || e.target.classList.contains('lightbox')) e.target.close();
            }
        });
    }

    function confirmDialog({ title = 'Are you sure?', text = '', label = 'Confirm' } = {}) {
        const dialog = $('#confirm-dialog');
        if (!dialog) return Promise.resolve(window.confirm(text || title));
        $('[data-confirm-title]', dialog).textContent = title;
        $('[data-confirm-text]', dialog).textContent = text;
        $('[data-confirm-button]', dialog).textContent = label;
        dialog.returnValue = '';
        dialog.showModal();
        $('[data-confirm-button]', dialog).focus();
        return new Promise((resolve) => {
            dialog.addEventListener('close', () => resolve(dialog.returnValue === 'confirm'), { once: true });
        });
    }

    // ---------------------------------------------------------------------
    // Form pipeline
    // ---------------------------------------------------------------------

    const FORM_HANDLERS = [];
    const onForm = (attr, handler) => FORM_HANDLERS.push([attr, handler]);

    function setLoading(btn, loading) {
        if (!btn) return;
        btn.classList.toggle('is-loading', loading);
        btn.disabled = loading;
    }

    function initForms() {
        document.addEventListener('submit', async (e) => {
            const form = e.target;
            if (form.method === 'dialog') return;

            if (form.hasAttribute('data-confirm')) {
                if (form.dataset.confirmed) {
                    delete form.dataset.confirmed;
                } else {
                    e.preventDefault();
                    const ok = await confirmDialog({
                        title: form.dataset.confirmTitle, text: form.dataset.confirm, label: form.dataset.confirmLabel || 'Confirm',
                    });
                    if (ok) { form.dataset.confirmed = '1'; form.requestSubmit(e.submitter || undefined); }
                    return;
                }
            }

            for (const [attr, handler] of FORM_HANDLERS) {
                if (form.hasAttribute(attr)) {
                    e.preventDefault();
                    handler(form, e.submitter);
                    return;
                }
            }

            if (DEMO && (form.method || '').toLowerCase() === 'post') {
                e.preventDefault();
                Demo.submit(form);
                return;
            }
            const btn = e.submitter || $('[type=submit], button:not([type])', form);
            if ((form.method || '').toLowerCase() === 'post' && btn) setTimeout(() => setLoading(btn, true), 0);
        });

        // Pages restored from the back/forward cache shouldn't keep spinners
        window.addEventListener('pageshow', (e) => {
            if (e.persisted) $$('.btn.is-loading').forEach((b) => setLoading(b, false));
        });

        // Ctrl/Cmd + Enter submits the surrounding form; Enter submits chat-style inputs
        document.addEventListener('keydown', (e) => {
            const el = e.target;
            if (el.tagName !== 'TEXTAREA' || e.key !== 'Enter' || e.isComposing) return;
            const mentionOpen = el._mentionPanel && !el._mentionPanel.hidden;
            if (mentionOpen) return;
            if (e.ctrlKey || e.metaKey || (el.hasAttribute('data-enter-submit') && !e.shiftKey && !matchMedia('(pointer: coarse)').matches)) {
                e.preventDefault();
                if (el.value.trim()) el.form?.requestSubmit();
            }
        });
    }

    // ---------------------------------------------------------------------
    // Posts: reactions, bookmarks, sharing, deleting, clamping
    // ---------------------------------------------------------------------

    function bump(el) {
        if (!el) return;
        el.classList.remove('is-bumping');
        void el.offsetWidth;
        el.classList.add('is-bumping');
    }

    function setCount(root, key, value) {
        $$(`[data-count="${key}"]`, root).forEach((el) => {
            const text = compact(value);
            if (el.textContent !== text) { el.textContent = text; bump(el); }
        });
    }

    function pop(btn) {
        btn.classList.remove('is-popping');
        void btn.offsetWidth;
        btn.classList.add('is-popping');
    }

    onForm('data-react', async (form) => {
        const post = form.closest('[data-post]');
        const btn = $('button', form);
        pop(btn);
        try {
            const data = await request(form.action, { body: new FormData(form), form });
            $$('[data-reaction]', post).forEach((b) => {
                const active = b.dataset.reaction === data.reaction;
                b.classList.toggle('is-active', active);
                b.setAttribute('aria-pressed', String(active));
            });
            setCount(post, 'like', data.like_count);
            setCount(post, 'dislike', data.dislike_count);
        } catch (err) { toast(err.message, 'danger'); }
    });

    onForm('data-bookmark', async (form) => {
        const btn = $('button', form);
        pop(btn);
        try {
            const data = await request(form.action, { body: new FormData(form), form });
            btn.classList.toggle('is-active', data.bookmarked);
            btn.setAttribute('aria-pressed', String(data.bookmarked));
            toast(data.message, data.bookmarked ? 'success' : 'info', 2500);
            if (!data.bookmarked && $('[data-bookmarks-page]')) {
                removeWithAnimation(form.closest('[data-post]'), () => {
                    if (!$('[data-bookmarks-page] [data-post]')) $('[data-empty-bookmarks]')?.removeAttribute('hidden');
                });
            }
        } catch (err) { toast(err.message, 'danger'); }
    });

    function removeWithAnimation(el, done) {
        if (!el) return;
        let finished = false;
        const finish = () => {
            if (finished) return;
            finished = true;
            el.remove();
            done?.();
        };
        if (reducedMotion()) return finish();
        el.style.height = `${el.offsetHeight}px`;
        el.classList.add('is-removing');
        el.addEventListener('animationend', (e) => { if (e.target === el) finish(); });
        setTimeout(finish, 450);
    }

    onForm('data-ajax-remove', async (form) => {
        const target = $(form.dataset.ajaxRemove);
        const post = form.closest('[data-post]');
        try {
            const data = await request(form.action, { body: new FormData(form), form });
            removeWithAnimation(target);
            if (typeof data.count === 'number' && post) setCount(post, 'comments', data.count);
            toast(data.message || 'Deleted', 'success', 2500);
        } catch (err) { toast(err.message, 'danger'); }
    });

    onForm('data-redirect', async (form) => {
        try {
            const data = await request(form.action, { body: new FormData(form), form });
            toastAfterNavigation(data.message || 'Deleted');
            location.href = form.dataset.redirect;
        } catch (err) { toast(err.message, 'danger'); }
    });

    async function copyText(text) {
        try {
            await navigator.clipboard.writeText(text);
        } catch {
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            ta.remove();
        }
    }

    function initSharing() {
        document.addEventListener('click', async (e) => {
            const copy = e.target.closest('[data-copy]');
            if (copy) {
                await copyText(new URL(copy.dataset.copy, location.href).href);
                toast('Link copied to clipboard', 'success', 2500);
                return;
            }
            const share = e.target.closest('[data-share]');
            if (share) {
                const url = new URL(share.dataset.share, location.href).href;
                const title = share.dataset.shareTitle || document.title;
                if (navigator.share && matchMedia('(pointer: coarse)').matches) {
                    try {
                        await navigator.share({ title, url });
                        return;
                    } catch (err) {
                        if (err?.name === 'AbortError') return;
                        // Sharing unavailable here: fall back to copying the link
                    }
                }
                await copyText(url);
                toast('Link copied — share it anywhere!', 'success', 2500);
            }
        });
    }

    function enhancePosts(root = document) {
        $$('[data-clamp]', root).forEach((body) => {
            if (body.dataset.clampReady) return;
            body.dataset.clampReady = '1';
            requestAnimationFrame(() => {
                const limit = parseFloat(getComputedStyle(body).fontSize) * 1.65 * 7;
                if (body.scrollHeight <= limit + 24) return;
                body.classList.add('is-clamped');
                const more = document.createElement('button');
                more.type = 'button';
                more.className = 'post__more';
                more.textContent = 'Show more';
                more.addEventListener('click', () => { body.classList.remove('is-clamped'); more.remove(); });
                body.after(more);
            });
        });
        updateTimes(root);
    }

    // Double-click / double-tap a photo to like it; single click opens the lightbox
    function initMedia() {
        let clickTimer = null;
        document.addEventListener('click', (e) => {
            const img = e.target.closest('img[data-lightbox]');
            if (!img) return;
            clearTimeout(clickTimer);
            clickTimer = setTimeout(() => {
                const box = $('#lightbox');
                if (!box) return;
                $('[data-lightbox-img]', box).src = img.currentSrc || img.src;
                $('[data-lightbox-img]', box).alt = img.alt;
                box.showModal();
            }, 260);
        });
        document.addEventListener('dblclick', (e) => {
            const media = e.target.closest('[data-media]');
            if (!media) return;
            clearTimeout(clickTimer);
            e.preventDefault();
            const burst = document.createElement('span');
            burst.className = 'like-burst';
            burst.innerHTML = icon('heart');
            media.appendChild(burst);
            burst.addEventListener('animationend', () => burst.remove());
            const likeBtn = $('[data-reaction="like"]', media.closest('[data-post]'));
            if (likeBtn && !likeBtn.classList.contains('is-active')) likeBtn.form.requestSubmit();
        });
    }

    // ---------------------------------------------------------------------
    // Comments
    // ---------------------------------------------------------------------

    function openComments(post, focus = true) {
        const section = $('[data-comments]', post);
        if (!section) return false;
        section.classList.remove('is-collapsed');
        if (focus) {
            const ta = $('textarea', section);
            ta?.focus({ preventScroll: true });
            (ta || section).scrollIntoView({ block: 'nearest', behavior: reducedMotion() ? 'auto' : 'smooth' });
        }
        return true;
    }

    function initComments() {
        document.addEventListener('click', (e) => {
            const toggle = e.target.closest('[data-comment-toggle]');
            if (toggle) {
                const post = toggle.closest('[data-post]');
                if (post && $('[data-comments]', post) && !e.metaKey && !e.ctrlKey) {
                    e.preventDefault();
                    openComments(post);
                }
                return;
            }
            const more = e.target.closest('[data-show-comments]');
            if (more) {
                const section = more.closest('[data-comments]');
                $$('[data-extra-comment]', section).forEach((c) => c.removeAttribute('hidden'));
                more.remove();
                return;
            }
            const edit = e.target.closest('[data-edit-comment]');
            if (edit) { e.preventDefault(); startInlineEdit(edit); }
        });
    }

    onForm('data-comment-form', async (form) => {
        const ta = $('textarea', form);
        const btn = $('[type=submit]', form);
        if (!ta.value.trim()) return;
        btn.disabled = true;
        try {
            const data = await request(form.action, { body: new FormData(form), form });
            const list = $('[data-comment-list]', form.closest('[data-comments]'));
            const frag = htmlToElement(data.html);
            const li = frag.firstElementChild;
            list.appendChild(frag);
            enhancePosts(li);
            ta.value = '';
            ta.dispatchEvent(new Event('input'));
            setCount(form.closest('[data-post]'), 'comments', data.count);
            li?.scrollIntoView({ block: 'nearest', behavior: reducedMotion() ? 'auto' : 'smooth' });
        } catch (err) {
            toast(err.message, 'danger');
        } finally {
            btn.disabled = false;
        }
    });

    function startInlineEdit(link) {
        const li = link.closest('.comment');
        if (!li || $('.comment__edit', li)) return;
        const bubble = $('.comment__bubble', li);
        const actions = $('.comment__actions', li);
        const editor = document.createElement('form');
        editor.className = 'comment__edit';
        editor.innerHTML = `<textarea class="textarea" name="comment_content" required maxlength="1000" dir="auto" data-autogrow data-mentions></textarea>
            <div class="comment__edit-actions"><button type="button" class="btn btn--ghost btn--sm" data-cancel>Cancel</button>
            <button type="submit" class="btn btn--primary btn--sm">Save</button></div>`;
        const ta = $('textarea', editor);
        ta.value = link.dataset.raw || '';
        bubble.hidden = true;
        actions.hidden = true;
        bubble.after(editor);
        autogrow(ta);
        ta.focus();
        ta.setSelectionRange(ta.value.length, ta.value.length);
        const cancel = () => { editor.remove(); bubble.hidden = false; actions.hidden = false; };
        $('[data-cancel]', editor).addEventListener('click', cancel);
        editor.addEventListener('keydown', (e) => { if (e.key === 'Escape') { e.stopPropagation(); cancel(); } });
        editor.addEventListener('submit', async (e) => {
            e.preventDefault();
            const value = ta.value.trim();
            if (!value) return;
            const body = new FormData();
            body.set('comment_content', value);
            body.set('csrf_token', $('meta[name="csrf-token"]')?.content || '');
            const btn = $('[type=submit]', editor);
            setLoading(btn, true);
            try {
                const data = await request(link.href, { body, form: editor });
                const frag = htmlToElement(data.html);
                const fresh = frag.firstElementChild;
                li.replaceWith(frag);
                enhancePosts(fresh);
                toast('Comment updated', 'success', 2000);
            } catch (err) {
                toast(err.message, 'danger');
                setLoading(btn, false);
            }
        });
    }

    // ---------------------------------------------------------------------
    // Follow
    // ---------------------------------------------------------------------

    onForm('data-follow', async (form) => {
        const btn = $('button', form);
        setLoading(btn, true);
        try {
            const data = await request(form.action, { body: new FormData(form), form });
            const userId = (form.action.match(/\/follow\/(\d+)/) || [])[1];
            $$(`form[data-follow][action="${form.getAttribute('action')}"] button`).forEach((b) => {
                b.classList.toggle('is-following', data.following);
                b.classList.toggle('btn--outline', data.following);
                b.classList.toggle('btn--primary', !data.following);
                b.setAttribute('aria-pressed', String(data.following));
            });
            if (userId && typeof data.followers === 'number') {
                $$(`[data-follower-count="${userId}"]`).forEach((el) => { el.textContent = compact(data.followers); bump(el); });
            }
            toast(data.message, 'success', 2500);
        } catch (err) {
            toast(err.message, 'danger');
        } finally {
            setLoading(btn, false);
        }
    });

    // ---------------------------------------------------------------------
    // Text inputs: autogrow, counters, emoji, mentions
    // ---------------------------------------------------------------------

    function autogrow(ta) {
        ta.style.height = 'auto';
        ta.style.height = `${ta.scrollHeight + 2}px`;
    }

    function updateCounter(ta) {
        const form = ta.form;
        const max = Number(ta.maxLength) > 0 ? Number(ta.maxLength) : 5000;
        const len = ta.value.length;
        const ring = form && $('[data-char-ring]', form);
        if (ring) {
            const pct = Math.min(100, (len / max) * 100);
            ring.style.setProperty('--p', pct.toFixed(1));
            ring.classList.toggle('is-warn', pct >= 90 && pct < 100);
            ring.classList.toggle('is-over', pct >= 100);
            $('span', ring).textContent = max - len <= 200 ? String(max - len) : '';
            ring.title = `${len} / ${max} characters`;
        }
        const label = form && $('[data-char-label]', form);
        if (label) label.textContent = `${len} / ${max}`;
    }

    function insertAtCursor(ta, text) {
        const start = ta.selectionStart ?? ta.value.length, end = ta.selectionEnd ?? ta.value.length;
        ta.setRangeText(text, start, end, 'end');
        ta.focus();
        ta.dispatchEvent(new Event('input', { bubbles: true }));
    }

    const EMOJI = ['😀', '😂', '🥹', '😍', '🥰', '😎', '🤩', '🤔', '😅', '😭', '😡', '🥳', '👍', '👏', '🙌', '🙏',
        '💪', '👀', '🔥', '✨', '💯', '🎉', '❤️', '💜', '💙', '💚', '⭐', '🌟', '☀️', '🌙', '🌈', '☕',
        '🍕', '🎵', '📷', '✈️', '🚀', '💡', '📚', '💻', '⚽', '🏃', '🌊', '🌸', '🐍', '🇮🇶', '✅', '👋'];

    function initTextInputs() {
        $$('[data-autogrow]').forEach(autogrow);
        $$('[data-counter]').forEach(updateCounter);
        document.addEventListener('input', (e) => {
            const el = e.target;
            if (el.matches('[data-autogrow]')) autogrow(el);
            if (el.matches('[data-counter]')) updateCounter(el);
            if (el.matches('[data-count]')) {
                const out = $(`[data-count-for="${el.id}"]`);
                if (out) out.textContent = `${el.value.length}/${el.dataset.count}`;
            }
        });

        document.addEventListener('click', (e) => {
            const ins = e.target.closest('[data-insert]');
            if (ins) {
                const ta = $('textarea', ins.closest('form'));
                const prefix = ta.value && !/\s$/.test(ta.value.slice(0, ta.selectionStart)) ? ' ' : '';
                insertAtCursor(ta, prefix + ins.dataset.insert);
                return;
            }
            const toggle = e.target.closest('[data-emoji-toggle]');
            if (toggle) {
                let panel = toggle.parentElement.querySelector('.emoji-panel');
                if (!panel) {
                    panel = document.createElement('div');
                    panel.className = 'popover emoji-panel';
                    panel.setAttribute('role', 'menu');
                    panel.innerHTML = EMOJI.map((em) => `<button type="button" role="menuitem" data-emoji="${em}" aria-label="${em}">${em}</button>`).join('');
                    panel.hidden = true;
                    toggle.after(panel);
                }
                panel.hidden = !panel.hidden;
                toggle.setAttribute('aria-expanded', String(!panel.hidden));
                return;
            }
            const em = e.target.closest('[data-emoji]');
            if (em) {
                const ta = $('textarea', em.closest('form'));
                insertAtCursor(ta, em.dataset.emoji);
                return;
            }
            if (!e.target.closest('.emoji-panel')) $$('.emoji-panel').forEach((p) => { p.hidden = true; });
        });
        initMentions();
    }

    function initMentions() {
        const fetchUsers = debounce(async (ta, query) => {
            try {
                const data = await getJSON(withQuery(URLS.suggest, { q: '@' + query }));
                renderMentionPanel(ta, data.users || []);
            } catch { /* ignore */ }
        }, 140);

        document.addEventListener('input', (e) => {
            const ta = e.target;
            if (!ta.matches('[data-mentions]')) return;
            const before = ta.value.slice(0, ta.selectionStart);
            const m = before.match(/(?:^|[^\w@])@([A-Za-z0-9_]{1,30})$/);
            if (m) fetchUsers(ta, m[1]);
            else hideMentionPanel(ta);
        });

        document.addEventListener('keydown', (e) => {
            const ta = e.target;
            const panel = ta._mentionPanel;
            if (!panel || panel.hidden) return;
            const items = $$('.search__item', panel);
            let i = items.findIndex((it) => it.classList.contains('is-active'));
            if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
                e.preventDefault();
                i = (i + (e.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length;
                items.forEach((it, j) => it.classList.toggle('is-active', j === i));
            } else if (e.key === 'Enter' || e.key === 'Tab') {
                e.preventDefault();
                (items[i] || items[0])?.click();
            } else if (e.key === 'Escape') {
                e.stopPropagation();
                hideMentionPanel(ta);
            }
        }, true);

        document.addEventListener('focusout', (e) => {
            if (e.target._mentionPanel) setTimeout(() => hideMentionPanel(e.target), 150);
        });
    }

    function renderMentionPanel(ta, users) {
        if (!users.length) return hideMentionPanel(ta);
        let panel = ta._mentionPanel;
        if (!panel) {
            panel = document.createElement('div');
            panel.className = 'popover mention-panel';
            panel.setAttribute('role', 'listbox');
            ta.parentElement.appendChild(panel);
            ta._mentionPanel = panel;
        }
        panel.innerHTML = '';
        users.forEach((u, i) => {
            const item = userItem(u, 'button');
            item.classList.toggle('is-active', i === 0);
            item.addEventListener('mousedown', (e) => e.preventDefault());
            item.addEventListener('click', () => {
                const before = ta.value.slice(0, ta.selectionStart);
                const start = before.lastIndexOf('@');
                ta.setRangeText(`@${u.handle} `, start, ta.selectionStart, 'end');
                ta.dispatchEvent(new Event('input', { bubbles: true }));
                hideMentionPanel(ta);
                ta.focus();
            });
            panel.appendChild(item);
        });
        panel.style.top = `${ta.offsetTop + ta.offsetHeight + 4}px`;
        panel.hidden = false;
    }

    function hideMentionPanel(ta) {
        if (ta._mentionPanel) ta._mentionPanel.hidden = true;
    }

    function avatarHTML(u, size = 'sm') {
        const inner = u.avatar ? `<img src="${escapeHTML(u.avatar)}" alt="">` : `<span aria-hidden="true">${escapeHTML(u.initials || '?')}</span>`;
        return `<span class="avatar avatar--${size}" style="--avatar-hue:${Number(u.hue) || 200}">${inner}</span>`;
    }

    function userItem(u, tag = 'a') {
        const el = document.createElement(tag);
        el.className = 'search__item';
        if (tag === 'a') el.href = u.url || userUrl(u.handle);
        else el.type = 'button';
        el.setAttribute('role', 'option');
        el.innerHTML = `${avatarHTML(u)}<span class="truncate"><span class="name"></span><small></small></span>`;
        $('.name', el).textContent = u.name;
        $('small', el).textContent = '@' + u.handle;
        return el;
    }

    // ---------------------------------------------------------------------
    // Composer: images, drafts, AJAX publishing
    // ---------------------------------------------------------------------

    function validImage(file) {
        if (!file) return false;
        if (!IMAGE_TYPES.includes(file.type)) { toast('Please choose a PNG, JPG, GIF or WEBP image.', 'danger'); return false; }
        if (file.size > MAX_UPLOAD) { toast('That image is larger than 16 MB.', 'danger'); return false; }
        return true;
    }

    function setInputFile(input, file) {
        const dt = new DataTransfer();
        dt.items.add(file);
        input.files = dt.files;
        input.dispatchEvent(new Event('change', { bubbles: true }));
    }

    function showImagePreview(form, file) {
        const preview = $('[data-image-preview]', form);
        if (!preview) return;
        const img = $('img', preview);
        if (img.dataset.objectUrl) URL.revokeObjectURL(img.dataset.objectUrl);
        img.dataset.objectUrl = URL.createObjectURL(file);
        img.src = img.dataset.objectUrl;
        preview.hidden = false;
        const flag = $('[data-remove-flag]', form);
        if (flag) flag.value = '';
    }

    function clearImage(form) {
        const input = $('[data-image-input]', form);
        if (input) input.value = '';
        const preview = $('[data-image-preview]', form);
        if (preview) { preview.hidden = true; $('img', preview).removeAttribute('src'); }
    }

    function initComposer() {
        document.addEventListener('change', (e) => {
            const input = e.target;
            if (input.matches('[data-image-input]')) {
                const file = input.files[0];
                if (!file) return;
                if (!validImage(file)) { input.value = ''; return; }
                showImagePreview(input.form, file);
            } else if (input.matches('[data-preview-target]')) {
                const file = input.files[0];
                if (!file || !validImage(file)) { input.value = ''; return; }
                const target = $(input.dataset.previewTarget);
                if (!target) return;
                let img = $('img', target);
                if (!img) { img = document.createElement('img'); img.alt = ''; target.prepend(img); $('span[aria-hidden]', target)?.remove(); }
                img.src = URL.createObjectURL(file);
            } else if (input.type === 'file' && input.closest('[data-dropzone]') && !input.matches('[data-image-input]')) {
                const zone = input.closest('[data-dropzone]');
                const file = input.files[0];
                if (!file) return;
                if (!validImage(file)) { input.value = ''; return; }
                const preview = $('[data-dropzone-preview]', zone);
                if (preview) preview.innerHTML = `<img src="${URL.createObjectURL(file)}" alt="">`;
                const name = $('[data-dropzone-name]', zone);
                if (name) name.textContent = file.name;
            }
        });

        document.addEventListener('click', (e) => {
            const remove = e.target.closest('[data-remove-image]');
            if (!remove) return;
            const form = remove.closest('form');
            clearImage(form);
            const flag = $('[data-remove-flag]', form);
            if (flag) flag.value = '1';
        });

        // Drag & drop and paste images into composers and dropzones
        const dropTargets = '[data-composer], [data-dropzone]';
        ['dragenter', 'dragover'].forEach((type) => document.addEventListener(type, (e) => {
            const zone = e.target.closest(dropTargets);
            if (!zone || !e.dataTransfer?.types?.includes('Files')) return;
            e.preventDefault();
            zone.classList.add('is-dragover');
        }));
        ['dragleave', 'drop'].forEach((type) => document.addEventListener(type, (e) => {
            const zone = e.target.closest(dropTargets);
            if (!zone) return;
            zone.classList.remove('is-dragover');
            if (type !== 'drop' || !e.dataTransfer?.files?.length) return;
            e.preventDefault();
            const input = $('input[type=file]', zone);
            const file = e.dataTransfer.files[0];
            if (input && validImage(file)) setInputFile(input, file);
        }));
        document.addEventListener('paste', (e) => {
            const form = e.target.closest?.('[data-composer]');
            const input = form && $('[data-image-input]', form);
            const file = [...(e.clipboardData?.files || [])].find((f) => f.type.startsWith('image/'));
            if (input && file && validImage(file)) { e.preventDefault(); setInputFile(input, file); toast('Image added from clipboard', 'info', 2000); }
        });

        // Drafts
        const composer = $('[data-composer][data-draft]');
        if (composer) {
            const title = $('[name=post_title]', composer), content = $('[name=post_content]', composer);
            const status = $('[data-draft-status]', composer);
            const draft = store.get('postfy:draft');
            const preset = (() => { try { const t = sessionStorage.getItem('postfy:compose-text'); sessionStorage.removeItem('postfy:compose-text'); return t; } catch { return null; } })();
            if (!title.value && !content.value && draft && (draft.title || draft.content)) {
                title.value = draft.title || '';
                content.value = draft.content || '';
                if (status) status.textContent = 'Draft restored';
            }
            if (preset) { content.value = preset + content.value; content.focus(); }
            autogrow(content);
            updateCounter(content);
            const save = debounce(() => {
                if (title.value || content.value) {
                    store.set('postfy:draft', { title: title.value, content: content.value });
                    if (status) status.textContent = 'Draft saved';
                } else {
                    store.remove('postfy:draft');
                    if (status) status.textContent = '';
                }
            }, 500);
            composer.addEventListener('input', save);
            if (!composer.hasAttribute('data-ajax-post')) composer.addEventListener('submit', () => store.remove('postfy:draft'));
        }

        // "New post" buttons focus the inline composer when there is one
        document.addEventListener('click', (e) => {
            const link = e.target.closest('[data-compose]');
            if (!link || e.metaKey || e.ctrlKey) return;
            const inline = $('[data-composer][data-ajax-post]');
            const text = link.dataset.composeText;
            if (!inline) {
                if (text) { try { sessionStorage.setItem('postfy:compose-text', text); } catch { /* ignore */ } }
                return;
            }
            e.preventDefault();
            focusComposer(inline, text);
        });
    }

    function focusComposer(form = $('[data-composer]'), text) {
        if (!form) { location.href = URLS.createPost; return; }
        form.scrollIntoView({ block: 'center', behavior: reducedMotion() ? 'auto' : 'smooth' });
        const title = $('[name=post_title]', form), content = $('[name=post_content]', form);
        if (text) { content.value = text + content.value; content.dispatchEvent(new Event('input', { bubbles: true })); }
        (title.value ? content : title).focus({ preventScroll: true });
    }

    onForm('data-ajax-post', async (form, submitter) => {
        const btn = submitter || $('[data-submit]', form);
        setLoading(btn, true);
        try {
            const data = await request(form.action, { body: new FormData(form), form });
            store.remove('postfy:draft');
            form.reset();
            clearImage(form);
            $$('textarea', form).forEach((ta) => { autogrow(ta); updateCounter(ta); });
            const status = $('[data-draft-status]', form);
            if (status) status.textContent = '';
            let feed = $('[data-prepend-new]');
            if (!feed && DEMO) {
                feed = document.createElement('div');
                feed.className = 'feed';
                feed.style.marginBottom = '18px';
                form.after(feed);
            }
            if (feed && data.html) {
                $('[data-feed-empty]')?.remove();
                $('.feed ~ .card .empty')?.closest('.card')?.remove();
                const frag = htmlToElement(data.html);
                const card = frag.firstElementChild;
                feed.prepend(frag);
                enhancePosts(card);
                card.classList.add('is-focused');
                setTimeout(() => card.classList.remove('is-focused'), 2200);
                toast(data.message || 'Posted!', 'success');
            } else {
                toastAfterNavigation(data.message || 'Posted!');
                location.href = data.url || URLS.home;
            }
        } catch (err) {
            toast(err.message, 'danger');
        } finally {
            setLoading(btn, false);
        }
    });

    // ---------------------------------------------------------------------
    // Search typeahead
    // ---------------------------------------------------------------------

    function initSearch() {
        const form = $('[data-search]');
        if (!form) return;
        const input = $('[data-search-input]', form);
        const panel = $('[data-search-panel]', form);
        let active = -1, lastQuery = '';

        const items = () => $$('.search__item', panel);
        const setActive = (i) => {
            const list = items();
            active = list.length ? (i + list.length) % list.length : -1;
            list.forEach((el, j) => {
                el.classList.toggle('is-active', j === active);
                el.setAttribute('aria-selected', String(j === active));
            });
        };
        const close = () => { panel.hidden = true; active = -1; };

        const render = (q, data) => {
            panel.innerHTML = '';
            const users = data.users || [], tags = data.tags || [];
            if (users.length) {
                panel.insertAdjacentHTML('beforeend', '<div class="search__label">People</div>');
                users.forEach((u) => panel.appendChild(userItem(u)));
            }
            if (tags.length) {
                panel.insertAdjacentHTML('beforeend', '<div class="search__label">Hashtags</div>');
                tags.forEach((t) => {
                    const a = document.createElement('a');
                    a.className = 'search__item';
                    a.href = t.url || tagUrl(t.name);
                    a.setAttribute('role', 'option');
                    a.innerHTML = `<span class="search__tag-icon">${icon('hash', 'icon--sm')}</span><span><span class="name"></span><small>${t.count} post${t.count === 1 ? '' : 's'}</small></span>`;
                    $('.name', a).textContent = '#' + t.name;
                    panel.appendChild(a);
                });
            }
            if (!DEMO || users.length || tags.length) {
                const all = document.createElement('a');
                all.className = 'search__item';
                all.href = withQuery(URLS.search, { q });
                all.setAttribute('role', 'option');
                all.innerHTML = `<span class="search__tag-icon">${icon('search', 'icon--sm')}</span><span>Search for “<strong></strong>”</span>`;
                $('strong', all).textContent = q;
                if (DEMO) all.addEventListener('click', (e) => { e.preventDefault(); Demo.search(q); });
                panel.appendChild(all);
            } else {
                panel.insertAdjacentHTML('beforeend', '<p class="search__empty">No people or hashtags match.</p>');
            }
            panel.hidden = false;
            setActive(-1);
        };

        const lookup = debounce(async (q) => {
            try {
                const data = await getJSON(withQuery(URLS.suggest, { q }));
                if (q === input.value.trim()) render(q, data);
            } catch { /* ignore */ }
        }, 160);

        input.addEventListener('input', () => {
            const q = input.value.trim();
            if (q === lastQuery) return;
            lastQuery = q;
            if (q) lookup(q); else close();
        });
        input.addEventListener('focus', () => { if (input.value.trim() && panel.children.length) panel.hidden = false; });
        input.addEventListener('keydown', (e) => {
            if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
                if (panel.hidden) return;
                e.preventDefault();
                setActive(active + (e.key === 'ArrowDown' ? 1 : -1));
            } else if (e.key === 'Enter' && active >= 0 && !panel.hidden) {
                e.preventDefault();
                items()[active].click();
            } else if (e.key === 'Escape') {
                close();
                input.blur();
                form.classList.remove('is-open');
            }
        });
        document.addEventListener('click', (e) => {
            if (e.target.closest('[data-search-open]')) {
                form.classList.add('is-open');
                input.focus();
                return;
            }
            if (!form.contains(e.target)) { close(); if (!input.value) form.classList.remove('is-open'); }
        });
        if (DEMO) {
            $$('form[role=search]').forEach((f) => f.addEventListener('submit', (e) => {
                if (f.hasAttribute('data-live-filter')) { e.preventDefault(); return; }
                e.preventDefault();
                Demo.search($('input[name=q]', f).value.trim());
            }));
        }
    }

    function focusSearch() {
        const form = $('[data-search]');
        if (!form) return;
        form.classList.add('is-open');
        const input = $('[data-search-input]', form);
        input.focus();
        input.select();
    }

    // Client-side filtering for the people grid and conversation list
    function initFilters() {
        const people = $('[data-live-filter] input');
        if (people) {
            people.addEventListener('input', () => {
                const q = people.value.trim().toLowerCase().replace(/^@/, '');
                $$('.person-card').forEach((card) => {
                    card.hidden = q && !card.textContent.toLowerCase().includes(q);
                });
            });
        }
        const convo = $('[data-convo-filter]');
        if (convo) {
            convo.addEventListener('input', () => {
                const q = convo.value.trim().toLowerCase();
                $$('[data-convo-name]').forEach((a) => {
                    a.closest('li').hidden = q && !a.dataset.convoName.includes(q);
                });
            });
        }
    }

    // ---------------------------------------------------------------------
    // Infinite scroll & live updates
    // ---------------------------------------------------------------------

    function initInfiniteScroll() {
        const loader = $('[data-infinite]');
        if (!loader || !('IntersectionObserver' in window)) return;
        let loading = false;
        const io = new IntersectionObserver(async (entries) => {
            if (!entries.some((en) => en.isIntersecting) || loading) return;
            loading = true;
            try {
                const data = await getJSON(loader.dataset.infinite);
                const target = $(loader.dataset.target || '#feed');
                const frag = htmlToElement(data.html);
                const nodes = [...frag.children];
                target.appendChild(frag);
                nodes.forEach((n) => enhancePosts(n));
                if (data.next) {
                    loader.dataset.infinite = data.next;
                } else {
                    io.disconnect();
                    loader.outerHTML = `<div class="feed-end">${icon('check-circle')}<strong>You're all caught up</strong><span>You've seen everything here.</span></div>`;
                }
            } catch (err) {
                io.disconnect();
                loader.innerHTML = `<button type="button" class="btn btn--outline btn--block">${icon('refresh', 'icon--sm')} Couldn't load more — retry</button>`;
                $('button', loader).addEventListener('click', () => { loader.innerHTML = ''; initInfiniteScroll(); });
            } finally {
                loading = false;
            }
        }, { rootMargin: '600px 0px' });
        io.observe(loader);
    }

    function setBadge(name, count) {
        $$(`[data-badge="${name}"]`).forEach((el) => {
            const changed = el.textContent !== String(count);
            el.textContent = count > 99 ? '99+' : count;
            el.hidden = !count;
            if (changed && count) { el.style.animation = 'none'; void el.offsetWidth; el.style.animation = ''; }
        });
    }

    function initPolling() {
        if (!CONFIG.user || DEMO) return;
        const baseTitle = document.title.replace(/^\(\d+\+?\)\s*/, '');
        const pollCounts = async () => {
            if (document.hidden) return;
            try {
                const data = await getJSON(URLS.counts);
                setBadge('notifications', data.notifications);
                setBadge('messages', data.messages);
                const total = data.notifications + data.messages;
                document.title = total ? `(${total}) ${baseTitle}` : baseTitle;
            } catch { /* ignore */ }
        };
        setInterval(pollCounts, 30000);
        document.addEventListener('visibilitychange', () => { if (!document.hidden) pollCounts(); });

        const feed = $('[data-latest-id]');
        const pill = $('[data-new-posts]');
        if (feed && pill) {
            setInterval(async () => {
                if (document.hidden) return;
                try {
                    const data = await getJSON(withQuery(URLS.feedNew, { after: feed.dataset.latestId }));
                    if (data.count > 0) {
                        $('[data-new-posts-label]', pill).textContent = `${data.count} new post${data.count === 1 ? '' : 's'}`;
                        pill.hidden = false;
                    }
                } catch { /* ignore */ }
            }, 45000);
        }
    }

    // ---------------------------------------------------------------------
    // Messages
    // ---------------------------------------------------------------------

    function initMessages() {
        const thread = $('[data-thread]');
        if (!thread) return;
        const scrollDown = (smooth) => thread.scrollTo({ top: thread.scrollHeight, behavior: smooth && !reducedMotion() ? 'smooth' : 'auto' });
        scrollDown(false);
        const seen = $('[data-seen]', thread);
        const append = (html) => {
            const frag = htmlToElement(html);
            const nodes = [...frag.children];
            thread.insertBefore(frag, seen);
            nodes.forEach((n) => updateTimes(n));
            const nearBottom = thread.scrollHeight - thread.scrollTop - thread.clientHeight < 240;
            if (nearBottom) scrollDown(true);
        };

        onForm('data-message-form', async (form) => {
            const ta = $('textarea', form);
            const btn = $('[type=submit]', form);
            if (!ta.value.trim()) return;
            btn.disabled = true;
            try {
                const data = await request(form.action, { body: new FormData(form), form });
                if (seen) seen.hidden = true;
                append(data.html);
                scrollDown(true);
                ta.value = '';
                autogrow(ta);
                ta.focus();
            } catch (err) {
                toast(err.message, 'danger');
            } finally {
                btn.disabled = false;
            }
        });

        if (DEMO) return;
        setInterval(async () => {
            if (document.hidden) return;
            try {
                const data = await getJSON(withQuery(thread.dataset.pollUrl, { after: thread.dataset.lastId }));
                if (data.html) { append(data.html); thread.dataset.lastId = data.last_id; }
                const mine = $$('.msg--mine', thread).pop();
                const last = $$('.msg', thread).pop();
                if (seen && mine && last === mine && data.seen_id >= Number(mine.dataset.messageId)) seen.hidden = false;
            } catch { /* ignore */ }
        }, 4000);
    }

    function initPeoplePicker() {
        const input = $('[data-people-picker]');
        if (!input) return;
        const results = $('[data-people-results]');
        const lookup = debounce(async () => {
            const q = input.value.trim();
            if (!q) { results.innerHTML = ''; return; }
            try {
                const data = await getJSON(withQuery(URLS.suggest, { q: '@' + q.replace(/^@/, '') }));
                results.innerHTML = '';
                const users = (data.users || []).filter((u) => u.handle !== CONFIG.user);
                if (!users.length) { results.innerHTML = '<p class="search__empty">No people found.</p>'; return; }
                users.forEach((u) => {
                    const a = userItem(u);
                    a.href = (URLS.conversation || '').replace('__USER__', encodeURIComponent(u.handle));
                    results.appendChild(a);
                });
            } catch { /* ignore */ }
        }, 160);
        input.addEventListener('input', lookup);
    }

    // ---------------------------------------------------------------------
    // Reports
    // ---------------------------------------------------------------------

    function resetReportDialog() {
        const dialog = $('#report-dialog');
        if (!dialog) return;
        $('[data-report-post-id]', dialog).value = '';
        $('[data-report-heading]', dialog).textContent = 'Report an issue';
        $('[data-report-intro]', dialog).textContent = "Found a bug or something that shouldn't be here? Tell us and our moderators will take a look.";
    }

    function initReports() {
        document.addEventListener('click', (e) => {
            const btn = e.target.closest('[data-report-post]');
            if (!btn) return;
            const dialog = openDialog('report-dialog');
            if (!dialog) return;
            $('[data-report-post-id]', dialog).value = btn.dataset.reportPost;
            $('[data-report-heading]', dialog).textContent = 'Report post';
            $('[data-report-intro]', dialog).textContent = `Tell us what's wrong with “${btn.dataset.reportTitle}”. Reports are anonymous to the author.`;
            $('#report_title', dialog).value = '';
            $('#report_title', dialog).focus();
        });
        onForm('data-report-form', async (form) => {
            const btn = $('[type=submit]', form);
            setLoading(btn, true);
            try {
                const data = await request(form.action, { body: new FormData(form), form });
                form.closest('dialog').close();
                form.reset();
                toast(data.message, 'success', 5000);
            } catch (err) {
                toast(err.message, 'danger');
            } finally {
                setLoading(btn, false);
            }
        });
    }

    // ---------------------------------------------------------------------
    // Account forms: passwords, usernames, email
    // ---------------------------------------------------------------------

    function passwordScore(pw) {
        if (!pw) return 0;
        let score = 0;
        if (pw.length >= 6) score++;
        if (pw.length >= 10) score++;
        if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
        if (/\d/.test(pw) && /[^A-Za-z0-9]/.test(pw)) score++;
        return Math.max(1, Math.min(4, score));
    }

    function initAccountForms() {
        document.addEventListener('click', (e) => {
            const btn = e.target.closest('[data-toggle-password]');
            if (!btn) return;
            const input = $('input', btn.closest('.input-wrap'));
            const show = input.type === 'password';
            input.type = show ? 'text' : 'password';
            btn.innerHTML = icon(show ? 'eye-off' : 'eye');
            btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
        });

        $$('[data-strength]').forEach((input) => {
            const field = input.closest('.field');
            const meter = $('[data-strength-meter]', field);
            const label = $('[data-strength-label]', field);
            const labels = ['', 'Weak — try making it longer', 'Fair — add numbers or symbols', 'Good password', 'Strong password 💪'];
            input.addEventListener('input', () => {
                const s = input.value ? passwordScore(input.value) : 0;
                meter.dataset.score = s;
                if (label) label.textContent = labels[s] || ' ';
            });
        });

        $$('[data-match]').forEach((input) => {
            const other = $(input.dataset.match);
            const check = () => input.setCustomValidity(input.value && input.value !== other.value ? "Passwords don't match" : '');
            input.addEventListener('input', check);
            other.addEventListener('input', check);
        });

        const email = $('[data-email-field]');
        if (email) {
            const box = $('[data-email-password]');
            email.addEventListener('input', () => {
                const changed = email.value.trim().toLowerCase() !== email.dataset.original.toLowerCase();
                box.hidden = !changed;
                $('input', box).required = changed;
            });
        }

        const username = $('[data-username-check]');
        if (username) {
            const status = $('[data-username-status]');
            const preview = $('[data-username-preview]');
            let edited = !!username.value;
            const original = username.value;
            const check = debounce(async () => {
                const value = username.value.trim().replace(/^@/, '').toLowerCase();
                if (preview) preview.textContent = value || '…';
                if (!value || value === original.toLowerCase()) { status.textContent = ''; status.className = 'field__status'; return; }
                if (!/^[a-z0-9_]{3,30}$/.test(value)) {
                    status.textContent = '3–30 letters, numbers or _';
                    status.className = 'field__status is-bad';
                    return;
                }
                try {
                    const data = await getJSON(withQuery(URLS.username, { username: value }));
                    status.textContent = data.available ? '✓ Available' : data.message;
                    status.className = `field__status ${data.available ? 'is-ok' : 'is-bad'}`;
                } catch { /* ignore */ }
            }, 350);
            username.addEventListener('input', () => { edited = true; check(); });
            $$('[data-username-source]').forEach((src) => src.addEventListener('input', () => {
                if (edited && username.value) return;
                const first = $('#first_name')?.value || '', last = $('#last_name')?.value || '';
                const guess = `${first}_${last}`.toLowerCase().normalize('NFKD').replace(/[^a-z0-9_]/g, '').replace(/^_+|_+$/g, '').slice(0, 30);
                if (guess.length >= 3) { username.value = guess; check(); }
                edited = false;
            }));
        }
    }

    // ---------------------------------------------------------------------
    // Relative time
    // ---------------------------------------------------------------------

    function timeAgo(date) {
        const s = (Date.now() - date.getTime()) / 1000;
        if (s < 60) return 'just now';
        if (s < 3600) return `${Math.floor(s / 60)}m`;
        if (s < 86400) return `${Math.floor(s / 3600)}h`;
        if (s < 604800) return `${Math.floor(s / 86400)}d`;
        const sameYear = date.getFullYear() === new Date().getFullYear();
        return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric', ...(sameYear ? {} : { year: 'numeric' }) });
    }

    function updateTimes(root = document) {
        $$('time[data-relative]', root).forEach((t) => {
            const d = new Date(t.getAttribute('datetime'));
            if (isNaN(d)) return;
            t.textContent = timeAgo(d);
            if (!t.dataset.localTitle) {
                t.title = d.toLocaleString(undefined, { dateStyle: 'full', timeStyle: 'short' });
                t.dataset.localTitle = '1';
            }
        });
    }

    // ---------------------------------------------------------------------
    // Keyboard shortcuts
    // ---------------------------------------------------------------------

    function initShortcuts() {
        let pendingG = false, gTimer = null, focusIndex = -1;
        const posts = () => $$('main [data-post]');
        const focused = () => posts()[focusIndex];
        const go = (url) => { if (url) location.href = url; };

        const focusPost = (delta) => {
            const list = posts();
            if (!list.length) return;
            list[focusIndex]?.classList.remove('is-focused');
            focusIndex = Math.max(0, Math.min(list.length - 1, focusIndex + delta));
            const post = list[focusIndex];
            post.classList.add('is-focused');
            post.focus({ preventScroll: true });
            post.scrollIntoView({ block: 'center', behavior: reducedMotion() ? 'auto' : 'smooth' });
        };

        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                closeDropdowns();
                $$('.emoji-panel').forEach((p) => { p.hidden = true; });
                return;
            }
            if (isTyping(e.target) || e.ctrlKey || e.metaKey || e.altKey || $('dialog[open]')) return;
            const key = e.key.toLowerCase();

            if (pendingG) {
                pendingG = false;
                clearTimeout(gTimer);
                const target = { h: URLS.home, e: URLS.people, n: URLS.notifications, m: URLS.messages, p: URLS.profile, b: URLS.bookmarks, s: URLS.settings }[key];
                if (target && CONFIG.user) { e.preventDefault(); go(target); }
                return;
            }

            switch (e.key) {
                case '/': e.preventDefault(); focusSearch(); break;
                case '?': e.preventDefault(); openDialog('shortcuts-dialog'); break;
                default:
                    switch (key) {
                        case 'g': pendingG = true; gTimer = setTimeout(() => { pendingG = false; }, 1200); break;
                        case 't': Appearance.toggle(); break;
                        case 'n': if (CONFIG.user) { e.preventDefault(); focusComposer($('[data-composer][data-ajax-post]') || null); } break;
                        case 'j': focusPost(1); break;
                        case 'k': focusPost(-1); break;
                        case 'l': focused() && $('[data-reaction="like"]', focused())?.form?.requestSubmit(); break;
                        case 'b': focused() && $('[data-bookmark]', focused())?.requestSubmit(); break;
                        case 'c': if (focused()) { e.preventDefault(); openComments(focused()); } break;
                        case 'o':
                        case 'enter': if (focused() && e.target === focused()) { const a = $('.post__title a', focused()); if (a) go(a.href); } break;
                        default: break;
                    }
            }
        });
    }

    // ---------------------------------------------------------------------
    // Misc page behaviours
    // ---------------------------------------------------------------------

    function initMisc() {
        // Back-to-top button
        const top = $('[data-back-to-top]');
        if (top) {
            const onScroll = () => top.classList.toggle('is-visible', scrollY > 900);
            addEventListener('scroll', onScroll, { passive: true });
            onScroll();
            top.addEventListener('click', () => scrollTo({ top: 0, behavior: reducedMotion() ? 'auto' : 'smooth' }));
        }

        // Back links use history when we came from inside Postfy
        document.addEventListener('click', (e) => {
            const back = e.target.closest('[data-back], [data-back-button]');
            if (!back) return;
            const internal = document.referrer && new URL(document.referrer).origin === location.origin;
            if (back.hasAttribute('data-back-button') || internal) {
                if (history.length > 1 && internal) { e.preventDefault(); history.back(); } else if (back.hasAttribute('data-back-button')) { location.href = CONFIG.user ? URLS.home : URLS.root; }
            }
        });

        // Onboarding checklist can be dismissed
        const onboarding = $('[data-onboarding]');
        if (onboarding) {
            if (store.get('postfy:onboarding-dismissed')) onboarding.hidden = true;
            $('[data-dismiss-onboarding]', onboarding)?.addEventListener('click', () => {
                store.set('postfy:onboarding-dismissed', true);
                removeWithAnimation(onboarding);
            });
        }

        // Settings scroll-spy
        const spy = $('[data-scrollspy]');
        if (spy && 'IntersectionObserver' in window) {
            const links = $$('a[href^="#"]', spy);
            const io = new IntersectionObserver((entries) => {
                entries.forEach((en) => {
                    if (!en.isIntersecting) return;
                    links.forEach((l) => l.classList.toggle('is-active', l.getAttribute('href') === `#${en.target.id}`));
                });
            }, { rootMargin: '-30% 0px -60% 0px' });
            links.forEach((l) => { const s = $(l.getAttribute('href')); if (s) io.observe(s); });
        }

        // Jump to a linked comment
        if (location.hash.startsWith('#comment-')) {
            const target = $(location.hash);
            if (target) {
                target.hidden = false;
                target.closest('[data-comments]')?.classList.remove('is-collapsed');
            }
        }

        setInterval(() => updateTimes(), 60000);
    }

    // ---------------------------------------------------------------------
    // Demo backend — used on the static GitHub Pages build, where there is
    // no server. It answers the same requests with realistic responses.
    // ---------------------------------------------------------------------

    const Demo = {
        seq: 900000,
        index() {
            if (!this._index) {
                try { this._index = JSON.parse($('#demo-index')?.textContent || '{}'); } catch { this._index = {}; }
            }
            return this._index;
        },
        nextId() { this.seq += 1; return String(this.seq); },
        fromTemplate(id) {
            const tpl = document.getElementById(id);
            return tpl ? tpl.innerHTML.replaceAll('999999', this.nextId()) : '';
        },
        count(post, key) {
            const el = $(`[data-count="${key}"]`, post);
            return el ? parseInt(el.textContent, 10) || 0 : 0;
        },
        async post(url, body, form) {
            await sleep(180 + Math.random() * 180);
            const path = new URL(url, location.href).pathname;
            const post = form?.closest?.('[data-post]');
            let m;
            if ((m = path.match(/\/react\/(like|dislike)\//))) {
                const kind = m[1];
                const current = $('[data-reaction].is-active', post)?.dataset.reaction || null;
                let likes = this.count(post, 'like'), dislikes = this.count(post, 'dislike');
                const adjust = (k, d) => { if (k === 'like') likes += d; else if (k === 'dislike') dislikes += d; };
                let reaction = kind;
                if (current === kind) { adjust(kind, -1); reaction = null; } else { adjust(current, -1); adjust(kind, 1); }
                return { ok: true, reaction, like_count: likes, dislike_count: dislikes };
            }
            if (/\/bookmark\//.test(path)) {
                const on = !$('button', form).classList.contains('is-active');
                return { ok: true, bookmarked: on, message: on ? 'Saved to bookmarks' : 'Removed from bookmarks' };
            }
            if (/\/follow\//.test(path)) {
                const btn = $('button', form);
                const following = !btn.classList.contains('is-following');
                const id = (path.match(/\/follow\/(\d+)/) || [])[1];
                const counter = id && $(`[data-follower-count="${id}"]`);
                const followers = counter ? (parseInt(counter.textContent, 10) || 0) + (following ? 1 : -1) : undefined;
                const name = btn.dataset.userName || 'them';
                return { ok: true, following, followers, message: following ? `You are now following ${name}` : `Unfollowed ${name}` };
            }
            if (/\/add_comment\//.test(path)) {
                const text = String(body.get('comment_content') || '').trim();
                const html = this.fromTemplate('tpl-comment');
                const frag = htmlToElement(html);
                const li = frag.firstElementChild;
                $('[data-comment-text]', li).innerHTML = richText(text);
                $('[data-edit-comment]', li)?.setAttribute('data-raw', text);
                const tmp = document.createElement('div');
                tmp.appendChild(frag);
                return { ok: true, html: tmp.innerHTML, count: this.count(post, 'comments') + 1 };
            }
            if ((m = path.match(/\/edit_comment\/(\d+)/))) {
                const li = document.getElementById(`comment-${m[1]}`);
                const text = String(body.get('comment_content') || '').trim();
                const clone = li.cloneNode(true);
                $('.comment__edit', clone)?.remove();
                $('.comment__bubble', clone).hidden = false;
                $('.comment__actions', clone).hidden = false;
                $('[data-comment-text]', clone).innerHTML = richText(text);
                $('[data-edit-comment]', clone).dataset.raw = text;
                return { ok: true, html: clone.outerHTML };
            }
            if (/\/delete_comment\//.test(path)) {
                return { ok: true, count: Math.max(0, this.count(post, 'comments') - 1), message: 'Comment deleted' };
            }
            if (/\/delete_post\//.test(path)) return { ok: true, message: 'Post deleted' };
            if (/\/create_post/.test(path)) {
                const title = String(body.get('post_title') || '').trim();
                const content = String(body.get('post_content') || '').trim();
                if (!title || !content) throw new Error('Please add a title and some content.');
                const frag = htmlToElement(this.fromTemplate('tpl-post'));
                const card = frag.firstElementChild;
                $('.post__title a', card).textContent = title;
                $('.post__body', card).innerHTML = richText(content);
                const file = body.get('post_image');
                if (file && file.size) {
                    $('.post__content', card).insertAdjacentHTML('afterend',
                        `<figure class="post__media" data-media><img src="${URL.createObjectURL(file)}" alt="" data-lightbox></figure>`);
                }
                const tmp = document.createElement('div');
                tmp.appendChild(frag);
                return { ok: true, html: tmp.innerHTML, message: 'Your post is live! 🎉 (demo — not saved)' };
            }
            if (/\/messages\//.test(path)) {
                const text = String(body.get('body') || '').trim();
                const frag = htmlToElement(this.fromTemplate('tpl-message'));
                $('.msg__bubble', frag.firstElementChild).innerHTML = richText(text);
                const tmp = document.createElement('div');
                tmp.appendChild(frag);
                return { ok: true, html: tmp.innerHTML };
            }
            if (/submit_report/.test(path)) return { ok: true, message: "Thanks for the report! (In this demo, reports aren't sent.)" };
            return { ok: true, message: "Demo mode — this change isn't saved." };
        },
        async get(url) {
            const u = new URL(url, location.href);
            const idx = this.index();
            if (/\/api\/search\/suggest/.test(u.pathname)) {
                const q = (u.searchParams.get('q') || '').toLowerCase();
                const needle = q.replace(/^[@#]/, '');
                const users = q.startsWith('#') ? [] : (idx.users || []).filter((x) =>
                    x.name.toLowerCase().includes(needle) || x.handle.includes(needle)).slice(0, 6);
                const tags = q.startsWith('@') ? [] : (idx.tags || []).filter((t) => t.name.includes(needle)).slice(0, 4);
                return { users, tags };
            }
            if (/\/api\/username-available/.test(u.pathname)) {
                const name = (u.searchParams.get('username') || '').toLowerCase();
                const taken = (idx.users || []).some((x) => x.handle === name);
                return { available: !taken, message: taken ? 'That username is already taken.' : `@${name} is available` };
            }
            if (/\/api\/messages\//.test(u.pathname)) return { html: '', last_id: Number(u.searchParams.get('after')) || 0, seen_id: 0 };
            if (/\/api\/feed\/new/.test(u.pathname)) return { count: 0 };
            if (/\/api\/counts/.test(u.pathname)) return { notifications: 0, messages: 0 };
            throw new Error('Not available in the demo');
        },
        submit(form) {
            if (form.hasAttribute('data-auth-form')) {
                const btn = $('[type=submit]', form);
                setLoading(btn, true);
                toastAfterNavigation('Welcome to the Postfy demo! 👋 You are signed in as Nour.');
                setTimeout(() => { location.href = $('[data-demo-root]')?.dataset.home || URLS.home; }, 450);
                return;
            }
            toast("Demo mode — changes aren't saved. Run Postfy locally to try this for real.", 'info');
        },
        search(q) {
            if (!q) return;
            const idx = this.index();
            const needle = q.toLowerCase().replace(/^[@#]/, '');
            const tag = (idx.tags || []).find((t) => t.name === needle) || (idx.tags || []).find((t) => t.name.includes(needle));
            const user = (idx.users || []).find((x) => x.handle === needle || x.name.toLowerCase().includes(needle));
            const target = q.startsWith('#') ? (tag || user) : (user || tag);
            if (target) location.href = target.url;
            else toast('Full-text search needs the Python server — try a person or #hashtag in this demo.', 'info', 5000);
        },
        init() {
            // Without a server, the full-page composer publishes in place too
            $$('[data-composer][data-draft]').forEach((f) => f.setAttribute('data-ajax-post', ''));
            // Signing out of the demo returns to the landing page
            document.addEventListener('click', (e) => {
                const a = e.target.closest('a[href]');
                if (!a) return;
                const href = a.getAttribute('href');
                if (/\/(logout|settings\/export)(\/|\/index\.html)?$/.test(href)) {
                    e.preventDefault();
                    if (href.includes('logout')) {
                        toastAfterNavigation('Signed out of the demo. Come back soon! 👋', 'info');
                        location.href = $('[data-demo-root]')?.dataset.landing || './';
                    } else {
                        toast("Data export isn't available in the demo.", 'info');
                    }
                } else if (/\/(post|edit_post)\/9\d{5}(\/|\/index\.html)?$/.test(href)) {
                    e.preventDefault();
                    toast('This post only exists in your browser — it disappears when you leave the page.', 'info');
                }
            });
        },
    };

    // ---------------------------------------------------------------------
    // Boot
    // ---------------------------------------------------------------------

    function init() {
        Appearance.init();
        initToasts();
        initDropdowns();
        initDialogs();
        initForms();
        initSharing();
        initMedia();
        initComments();
        initTextInputs();
        initComposer();
        initSearch();
        initFilters();
        initInfiniteScroll();
        initPolling();
        initMessages();
        initPeoplePicker();
        initReports();
        initAccountForms();
        initShortcuts();
        initMisc();
        if (DEMO) Demo.init();
        enhancePosts();
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();

    window.Postfy = { toast, confirm: confirmDialog, openDialog };
})();
