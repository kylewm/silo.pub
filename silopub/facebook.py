from flask import Blueprint, current_app, redirect, url_for, request, flash
from flask import make_response, session, abort
from flask.ext.wtf.csrf import generate_csrf, validate_csrf
from silopub import micropub
from silopub import util
from silopub.ext import db
from silopub.models import Account, Facebook
from urllib.parse import urlencode, parse_qs
import brevity
import html
import json
import re
import requests
import sys

SERVICE_NAME = 'facebook'
PERMISSION_SCOPES = 'publish_actions'


facebook = Blueprint('facebook', __name__)


@facebook.route('/facebook.com/<user_id>')
def proxy_homepage(user_id):
    account = Account.query.filter_by(
        service=SERVICE_NAME, user_id=user_id).first()

    if not account:
        abort(404)

    return util.render_proxy_homepage(account.sites[0], account.username)


@facebook.route('/facebook/authorize', methods=['POST'])
def authorize():
    try:
        current_app.logger.info('Redirecting to Facebook authorize')
        callback_uri = url_for('.callback', _external=True)
        return redirect(get_authorize_url(callback_uri))
    except:
        current_app.logger.exception('Starting Facebook authorization')
        flash(html.escape(str(sys.exc_info()[0])), 'danger')
        return redirect(url_for('views.index'))


@facebook.route('/facebook/callback')
def callback():
    callback_uri = url_for('.callback', _external=True)
    result = process_authenticate_callback(callback_uri)
    if 'error' in result:
        flash(result['error'], category='danger')
        return redirect(url_for('views.index'))
    account = Account.query.filter_by(
        service='facebook', user_id=result['user_id']).first()

    if not account:
        account = Account(service='facebook', user_id=result['user_id'])
        db.session.add(account)

    account.username = result['username']
    account.user_info = result['user_info']
    account.token = result['token']

    account.sites = [Facebook(
        url='https://www.facebook.com/{}'.format(account.user_id),
        # overloading "domain" to really mean "user's canonical url"
        domain='facebook.com/{}'.format(account.user_id),
        site_id=account.user_id)]

    db.session.commit()
    flash('Authorized {}: {}'.format(account.username, ', '.join(
        s.domain for s in account.sites)))
    return redirect(url_for('views.account', service=SERVICE_NAME,
                            username=account.username))


def get_authenticate_url(callback_uri):
    return 'https://graph.facebook.com/oauth/authenticate?' + urlencode({
        'client_id': current_app.config['FACEBOOK_CLIENT_ID'],
        'redirect_uri': callback_uri,
        'state': generate_csrf(),
    })


def get_authorize_url(callback_uri):
    return 'https://graph.facebook.com/oauth/authorize?' + urlencode({
        'client_id': current_app.config['FACEBOOK_CLIENT_ID'],
        'redirect_uri': callback_uri,
        'scope': PERMISSION_SCOPES,
        'state': generate_csrf(),
    })


def process_authenticate_callback(callback_uri):
    code = request.args.get('code')
    state = request.args.get('state')
    error = request.args.get('error')
    error_desc = request.args.get('error_description', '')

    if error:
        return {'error': 'Facebook auth canceled or failed with error: {}, '
                'description: {}'.format(error, error_desc)}

    if not validate_csrf(state):
        return {'error': 'csrf token mismatch in Facebook callback.'}

    r = requests.get('https://graph.facebook.com/oauth/access_token', params={
        'client_id': current_app.config['FACEBOOK_CLIENT_ID'],
        'client_secret': current_app.config['FACEBOOK_CLIENT_SECRET'],
        'redirect_uri': callback_uri,
        'code': code,
        'scope': PERMISSION_SCOPES,
    })

    if r.status_code // 100 != 2:
        error_obj = r.json()
        error = error_obj.get('error')
        error_desc = error_obj.get('error_description')
        return {'error': 'Error ({}) requesting access token: {}, '
                'description: {}' .format(r.status_code, error, error_desc)}

    payload = parse_qs(r.text)
    current_app.logger.info('auth responses from Facebook %s', payload)
    access_token = payload['access_token'][0]

    r = requests.get('https://graph.facebook.com/v2.5/me', params={
        'access_token': access_token,
    })

    if r.status_code // 100 != 2:
        error_obj = r.json()
        error = error_obj.get('error')
        error_desc = error_obj.get('error_description')
        return {'error': 'Error ({}) requesting authed user info: {}, '
                'description: {}' .format(r.status_code, error, error_desc)}

    user_info = r.json()
    current_app.logger.info('authed user info from Facebook %s', user_info)
    return {
        'token': access_token,
        'user_id': user_info.get('id'),
        'username': user_info.get('name'),
        'user_info': user_info,
    }


def publish(site):
    title = request.form.get('name')
    content = request.form.get('content[value]') or request.form.get('content')
    permalink = request.form.get('url')
    photo_file = request.files.get('photo')

    post_data = {}
    post_files = None
    api_endpoint = 'https://graph.facebook.com/v2.5/me/feed'

    if title and content:
        # this looks like an article
        post_data['message'] = '{}\n\n{}'.format(title, content)
        post_data['link'] = permalink
        post_data['name'] = title
    else:
        message = ('{} ({})'.format(content, permalink)
                   if content else '({})'.format(permalink))
        if photo_file:
            post_files = {'source': photo_file}
            post_data['caption'] = message
            # TODO support album id as alternative to 'me'
            api_endpoint = 'https://graph.facebook.com/v2.5/me/photos'
        else:
            post_data['message'] = message
            tokens = brevity.tokenize(content)
            # linkify the first url in the message
            linktok = next((tok for tok in tokens if tok.tag == 'link'), None)
            if linktok:
                post_data['link'] = linktok.content

    r = requests.post(api_endpoint, data=post_data, files=post_files)
    r.raise_for_status()

    resp_data = r.json()
    fbid = resp_data.get('post_id') or resp_data.get('id')
    resp = make_response('', 201)
    resp.headers['Location'] = 'https://www.facebook.com/{}'.format(fbid)
    return resp
