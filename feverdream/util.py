import urllib.parse
from flask import flash, current_app


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
