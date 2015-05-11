from flask import (
    Blueprint, redirect, url_for, current_app, request, abort, jsonify,
)
import requests
import urllib.parse
from feverdream.models import Site, Account
from feverdream.extensions import csrf
from feverdream import util
from sqlalchemy import func


PUBLISHERS = {}

micropub = Blueprint('micropub', __name__)


def publisher(service):
    def decorator(f):
        PUBLISHERS[service] = f
        return f
    return decorator


@csrf.exempt
@micropub.route('/micropub', methods=['GET', 'POST'])
def micropub_endpoint():
    current_app.logger.info(
        "received micropub request %s, args=%s, form=%s, headers=%s",
        request, request.args, request.form, request.headers)

    if request.method == 'GET':
        return 'This is the micropub endpoint.'

    bearer_prefix = 'Bearer '
    header_token = request.headers.get('authorization')
    if header_token and header_token.startswith(bearer_prefix):
        token = header_token[len(bearer_prefix):]
    else:
        token = request.form.get('access_token')

    if not token:
        err_msg = 'Micropub request is missing access_token'
        current_app.logger.warn(err_msg)
        return err_msg, 401

    r = requests.get('https://tokens.indieauth.com/token', headers={
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Bearer ' + token})

    if r.status_code // 100 != 2:
        err_msg = ('Access token rejected by indieauth.com with message {}'
                   .format(r.text))
        current_app.logger.warn(err_msg)
        return err_msg, 401

    current_app.logger.info(
        'indieauth.com confirms this is a good token %s', r.text)

    token_data = urllib.parse.parse_qs(r.text)
    me = token_data.get('me')[0]
    scope = token_data.get('scope')[0]
    client_id = token_data.get('client_id')[0]

    # indieauth has confirmed that me is who they say they are, so if we have
    # an access token for their api, then we should be good to go

    domain = urllib.parse.urlparse(me).netloc
    site = Site.query.filter(
        func.lower(Site.domain) == domain.lower()).first()

    if not site:
        err_msg = 'Could not find an authorization for {}.'.format(domain)
        current_app.logger.warn(err_msg)
        return err_msg, 401

    current_app.logger.info('Success! Publishing to %s', site)
    return PUBLISHERS[site.service](site)


def get_complex_content():
    lines = []
    for prop, headline in [('in-reply-to', 'In reply to'),
                           ('like-of', 'Liked'),
                           ('repost-of', 'Reposted'),
                           ('bookmark-of', 'Bookmarked')]:
        target = request.form.get(prop)
        if target:
            lines.append('<p>{} <a class="u-{}" href="{}">{}</a></p>'.format(
                headline, prop, target, util.prettify_url(target)))

    content = request.form.get('content')
    if content:
        lines.append(request.form.get('content'))

    return '\n'.join(lines)
