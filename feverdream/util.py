import urllib.parse
from flask import flash, current_app, make_response
import jwt
import random


def domain_for_url(url):
    p = urllib.parse.urlparse(url)
    return p.netloc


def prettify_url(url):
    p = urllib.parse.urlparse(url)
    pretty = p.netloc
    if p.path:
        pretty += p.path
    return pretty.rstrip('/')


def trim_nulls(obj):
    if isinstance(obj, list):
        return [trim_nulls(v) for v in obj if trim_nulls(v)]
    if isinstance(obj, dict):
        return {k: trim_nulls(v) for k, v in obj.items()
                if trim_nulls(v)}
    return obj


def check_request_failed(r, category='danger'):
    if r.status_code // 100 != 2:
        err_msg = 'Request to {} failed ({}): {}'.format(
            r.url, r.status_code, r.text)
        current_app.logger.error(err_msg)
        flash(err_msg, category=category)
        return True


def set_query_params(url, **kwargs):
    return url + ('&' if '?' in url else '?') + urllib.parse.urlencode(kwargs)


def urlenc_response(args, status=200):
    resp = make_response(urllib.parse.urlencode(args), status)
    resp.headers['Content-Type'] = 'application/x-www-form-urlencoded'
    return resp


def jwt_encode(obj):
    obj['nonce'] = random.randint(1000000, 2 ** 31)
    return jwt.encode(obj, current_app.config['SECRET_KEY'])


def jwt_decode(s):
    return jwt.decode(s, current_app.config['SECRET_KEY'])


def get_complex_content(data):
    """Augment content with content from additional fields like
    in-reply-to"""
    lines = []
    for prop, headline in [('in-reply-to', 'In reply to'),
                           ('like-of', 'Liked'),
                           ('repost-of', 'Reposted'),
                           ('bookmark-of', 'Bookmarked')]:
        target = data.get(prop)
        if target:
            lines.append('<p>{} <a class="u-{}" href="{}">{}</a></p>'.format(
                headline, prop, target, prettify_url(target)))

    content = data.get('content')
    if content:
        lines.append(data.get('content'))

    return '\n'.join(lines)
