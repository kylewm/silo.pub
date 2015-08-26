from silopub import util
from silopub.ext import db
from silopub.models import Account, Twitter
from flask import Blueprint, current_app, redirect, url_for, request, flash
from flask import make_response, session
from requests_oauthlib import OAuth1Session, OAuth1
import html
import requests
import sys


REQUEST_TOKEN_URL = 'https://api.twitter.com/oauth/request_token'
AUTHENTICATE_URL = 'https://api.twitter.com/oauth/authenticate'
AUTHORIZE_URL = 'https://api.twitter.com/oauth/authorize'
ACCESS_TOKEN_URL = 'https://api.twitter.com/oauth/access_token'
VERIFY_CREDENTIALS_URL = 'https://api.twitter.com/1.1/account/verify_credentials.json'

SERVICE_NAME = 'twitter'

twitter = Blueprint('twitter', __name__)


@twitter.route('/twitter/authorize', methods=['POST'])
def authorize():
    try:
        callback_uri = url_for('.callback', _external=True)
        return redirect(get_authorize_url(callback_uri))
    except:
        current_app.logger.exception('Starting Twitter authorization')
        flash(html.escape(str(sys.exc_info()[0])), 'danger')
        return redirect(url_for('views.index'))


@twitter.route('/twitter/callback')
def callback():
    try:
        callback_uri = url_for('.callback', _external=True)
        result = process_authenticate_callback(callback_uri)
        if 'error' in result:
            flash(result['error'], category='danger')
            return redirect(url_for('views.index'))

        account = Account.query.filter_by(
            service='twitter', user_id=result['user_id']).first()

        if not account:
            account = Account(service='twitter', user_id=result['user_id'])
            db.session.add(account)

        account.username = result['username']
        account.user_info = result['user_info']
        account.token = result['token']
        account.token_secret = result['secret']

        account.sites = [Twitter(
            url='https://twitter.com/{}'.format(account.username),
            domain='twitter.com',
            site_id=account.user_id)]

        db.session.commit()
        flash('Authorized {}: {}'.format(account.username, ', '.join(
            s.domain for s in account.sites)))
        return redirect(url_for('views.account', service=SERVICE_NAME,
                                username=account.username))

    except:
        current_app.logger.exception('During Tumblr authorization callback')
        flash(html.escape(str(sys.exc_info()[0])), 'danger')
        return redirect(url_for('views.index'))


def get_authenticate_url(callback_uri):
    oauth = OAuth1Session(
        client_key=current_app.config['TWITTER_CLIENT_KEY'],
        client_secret=current_app.config['TWITTER_CLIENT_SECRET'],
        callback_uri=callback_uri)
    r = oauth.fetch_request_token(REQUEST_TOKEN_URL)
    session['oauth_token_secret'] = r.get('oauth_token_secret')
    return oauth.authorization_url(AUTHENTICATE_URL)


def get_authorize_url(callback_uri):
    oauth = OAuth1Session(
        client_key=current_app.config['TWITTER_CLIENT_KEY'],
        client_secret=current_app.config['TWITTER_CLIENT_SECRET'],
        callback_uri=callback_uri)
    r = oauth.fetch_request_token(REQUEST_TOKEN_URL)
    session['oauth_token_secret'] = r.get('oauth_token_secret')
    return oauth.authorization_url(AUTHORIZE_URL)


def process_authenticate_callback(callback_uri):
    verifier = request.args.get('oauth_verifier')
    request_token = request.args.get('oauth_token')
    if not verifier or not request_token:
        # user declined
        return {'error': 'Twitter authorization declined'}

    request_token_secret = session.get('oauth_token_secret')
    oauth = OAuth1Session(
        client_key=current_app.config['TWITTER_CLIENT_KEY'],
        client_secret=current_app.config['TWITTER_CLIENT_SECRET'],
        resource_owner_key=request_token,
        resource_owner_secret=request_token_secret)
    oauth.parse_authorization_response(request.url)
    # get the access token and secret
    r = oauth.fetch_access_token(ACCESS_TOKEN_URL)
    token = r.get('oauth_token')
    secret = r.get('oauth_token_secret')

    user_info = oauth.get(VERIFY_CREDENTIALS_URL).json()
    user_id = user_info.get('id_str')
    username = user_info.get('screen_name')

    return {
        'token': token,
        'secret': secret,
        'user_id': user_id,
        'username': username,
        'user_info': user_info,
    }


def publish(site):
    auth = OAuth1(
        client_key=current_app.config['TWITTER_CLIENT_KEY'],
        client_secret=current_app.config['TWITTER_CLIENT_SECRET'],
        resource_owner_key=site.account.token,
        resource_owner_secret=site.account.token_secret)
