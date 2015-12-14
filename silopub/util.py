import datetime
import random
import re
import urllib.parse

from flask import flash, current_app, make_response, url_for, jsonify, session
from requests.exceptions import HTTPError, SSLError
import jwt
import mf2py


def looks_like_a_url(text):
    return re.match(
        r'(http|https|file|irc|mailto):/{0,3}[\w\-\.]*[a-z]{2,}',
        text, re.IGNORECASE) is not None


def domain_for_url(url, strip_prefix=False):
    p = urllib.parse.urlparse(url)
    domain = p.netloc
    if strip_prefix:
        for prefix in ('www.', 'mobile.', 'm.'):
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
    return domain


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


def generate_access_token(me, site_id, client_id, scope):
    # deprecated
    token = jwt_encode({
        'me': me,
        'site': site_id,
        'client_id': client_id,
        'scope': scope,
        'date_issued': datetime.datetime.utcnow().isoformat()
    })
    return token


def set_authed(sites):
    session['authed-sites'] = [s.id for s in sites]


def is_authed(site):
    return site.id in session.get('authed-sites', [])


def clear_authed(site):
    session.pop('authed-sites', None)


def get_complex_content(data):
    """Augment content with content from additional fields like
    in-reply-to"""
    lines = []
    for prop, headline in [('in-reply-to', 'In reply to'),
                           ('like-of', 'Liked'),
                           ('repost-of', 'Reposted'),
                           ('bookmark-of', 'Bookmarked')]:
        for target in get_possible_array_value(data, prop):
            lines.append('<p>{} <a class="u-{}" href="{}">{}</a></p>'.format(
                headline, prop, target, prettify_url(target)))

    content = (data.get('content[html]') or data.get('content')
               or data.get('summary'))
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
        d = mf2py.parse(url=original)
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


def render_proxy_homepage(name, url, photo):
    # TODO make endpoints visible because why not
    return """
<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <link rel="authorization_endpoint" href="{auth}">
        <link rel="token_endpoint" href="{token}">
        <link rel="micropub" href="{micropub}">
        <link rel="me" href="{me}">
    </head>
    <body>
        Micropub proxy for

        <div class="h-card">
          <img class="u-photo" src="{photo}"/>
          <a class="p-name u-url" href="{me}">{username}</a>
        </div>

    </body>
</html>""".format(
      auth=url_for('micropub.indieauth', _external=True),
      token=url_for('micropub.token_endpoint', _external=True),
      micropub=url_for('micropub.micropub_endpoint', _external=True),
      me=url, username=name, photo=photo)


def make_publish_success_response(location, data=None):
    current_app.logger.debug('Publish success, location=%s, data=%r',
                             location, data)
    resp = jsonify(data or {})
    resp.status_code = 201
    resp.headers['Location'] = location
    return resp


def make_publish_error_response(message):
    current_app.logger.error('Local error: %s', message)
    resp = jsonify({
        'error': message,
    })
    resp.status_code = 400
    return resp


def wrap_silo_error_response(r):
    current_app.logger.error('Upstream error: %r %s', r, r.text)
    resp_data = r.text
    try:
        resp_data = r.json()
    except:
        pass

    resp = jsonify({
        'error': 'Bad Upstream Response',
        'upstream-status': r.status_code,
        'upstream-data': resp_data,
    })
    resp.status_code = 400
    return resp


def get_possible_array_value(args, key):
    """Micropub uses PHP-style array params, like category[], to indicate
    a multi-valued key. Python doesn't do any special handling with
    these which means we have to work a little harder to support them.

    :param werkzeug.datastructures.MultiDict args: incoming request args
    :param string key: the bare key name (e.g. "category")

    :return list: the, possibly empty, list of values
    """
    if not args:
        return []
    if key in args:
        return [args.get(key)]
    return args.getlist(key + '[]')


def parse_geo_uri(uri):
    if uri and uri.startswith('geo:'):
        latlong = uri[4:].split(';')[0].split(',', 1)
        if len(latlong) == 2:
            return latlong
    return None, None
