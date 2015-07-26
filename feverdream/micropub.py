from feverdream import util
from feverdream.ext import csrf, redis
from feverdream.models import Site, Account
from flask import Blueprint, redirect, url_for, current_app, request, abort
from flask import jsonify
import datetime
import json
import requests
import urllib.parse

PUBLISHERS = {}

micropub = Blueprint('micropub', __name__)


def publisher(service):
    def decorator(f):
        PUBLISHERS[service] = f
        return f
    return decorator


@csrf.exempt
@micropub.route('/token', methods=['POST'])
def token_endpoint():
    code = request.form.get('code')
    me = request.form.get('me')
    redirect_uri = request.form.get('redirect_uri')
    client_id = request.form.get('client_id')
    state = request.form.get('state', '')

    datastr = redis.get('indieauth-code:{}'.format(code))
    if not datastr:
        return util.urlenc_response(
            {'error': 'Unrecognized or expired authorization code'}, 400)

    data = json.loads(datastr.decode('utf-8'))
    for key, value in [('me', me), ('client_id', client_id),
                       ('redirect_uri', redirect_uri), ('state', state)]:
        if data.get(key) != value:
            return util.urlenc_response({'error': key + ' mismatch'}, 400)

    # ok we're confirmed, create an access token
    scope = data.get('scope', '')
    site_id = data.get('site')

    token = util.jwt_encode({
        'me': me,
        'site': site_id,
        'client_id': client_id,
        'scope': scope,
        'date_issued': datetime.datetime.utcnow().isoformat()
    })

    return util.urlenc_response({
        'access_token': token,
        'me': me,
        'scope': scope,
    })


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

    token_data = util.jwt_decode(token)

    if not token_data:
        err_msg = 'Unrecognized token: {}' .format(token)
        current_app.logger.warn(err_msg)
        return err_msg, 401

    me = token_data.get('me')
    site_id = token_data.get('site')
    scope = token_data.get('scope')
    client_id = token_data.get('client_id')

    # indieauth has confirmed that me is who they say they are, so if we have
    # an access token for their api, then we should be good to go

    site = Site.query.get(site_id)

    if not site:
        err_msg = 'Could not find a site for site id {}.'.format(site_id)
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
