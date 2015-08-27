from flask import flash, current_app, make_response
from requests.exceptions import HTTPError, SSLError
import jwt
import mf2py
import random
import urllib.parse


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

    content = data.get('content') or data.get('summary')
    if content:
        lines.append(content)

    return '\n'.join(lines)


def posse_post_discovery(original, regex):
    """Given an original URL and a permalink regex, looks for
    silo-specific syndication URLs. If the original is a silo url,
    that url is returned; otherwise we fetch the source and attempt to
    look for u-syndication URLs.
    """
    if regex.match(original):
        return original

    try:
        d = mf2py.Parser(url=original).to_dict()
        urls = d['rels'].get('syndication', [])
        for item in d['items']:
            if 'h-entry' in item['type']:
                urls += item['properties'].get('syndication', [])
        for url in urls:
            if regex.match(url):
                return url
    except HTTPError:
        current_app.logger.exception('Could not fetch original')
    except SSLError:
        current_app.logger.exception('SSL Error')
    except Exception as e:
        current_app.logger.exception('MF2 Parser error: %s', e)
