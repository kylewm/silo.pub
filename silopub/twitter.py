import html
import requests
import sys
import json
import re
import urllib.parse

from flask import Blueprint, current_app, redirect, url_for, request, flash
from flask import make_response, session, abort
from requests_oauthlib import OAuth1Session, OAuth1
from silopub import util
from silopub import micropub
from silopub.ext import db
from silopub.models import Account, Twitter
import brevity

REQUEST_TOKEN_URL = 'https://api.twitter.com/oauth/request_token'
AUTHENTICATE_URL = 'https://api.twitter.com/oauth/authenticate'
AUTHORIZE_URL = 'https://api.twitter.com/oauth/authorize'
ACCESS_TOKEN_URL = 'https://api.twitter.com/oauth/access_token'
VERIFY_CREDENTIALS_URL = 'https://api.twitter.com/1.1/account/verify_credentials.json'
CREATE_STATUS_URL = 'https://api.twitter.com/1.1/statuses/update.json'
CREATE_WITH_MEDIA_URL = 'https://api.twitter.com/1.1/statuses/update_with_media.json'
RETWEET_STATUS_URL = 'https://api.twitter.com/1.1/statuses/retweet/{}.json'
FAVE_STATUS_URL = 'https://api.twitter.com/1.1/favorites/create.json'

TWEET_RE = re.compile(r'https?://(?:www\.|mobile\.)?twitter\.com/(\w+)/status(?:es)?/(\w+)')

SERVICE_NAME = 'twitter'

twitter = Blueprint('twitter', __name__)


@twitter.route('/twitter.com/<username>')
def proxy_homepage(username):
    account = Account.query.filter_by(
        service=SERVICE_NAME, username=username).first()

    if not account:
        abort(404)

    return util.render_proxy_homepage(account.sites[0], '@' + account.username)


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
            domain='twitter.com/{}'.format(account.username),
            site_id=account.user_id)]

        db.session.commit()
        flash('Authorized {}: {}'.format(account.username, ', '.join(
            s.domain for s in account.sites)))
        return redirect(url_for('views.setup_account', service=SERVICE_NAME,
                                username=account.username))

    except:
        current_app.logger.exception('During Tumblr authorization callback')
        flash(html.escape(str(sys.exc_info()[0])), 'danger')
        return redirect(url_for('views.index'))


def get_authenticate_url(callback_uri, me=None, **kwargs):
    oauth = OAuth1Session(
        client_key=current_app.config['TWITTER_CLIENT_KEY'],
        client_secret=current_app.config['TWITTER_CLIENT_SECRET'],
        callback_uri=callback_uri)
    r = oauth.fetch_request_token(REQUEST_TOKEN_URL)
    session['oauth_token_secret'] = r.get('oauth_token_secret')

    base_url = AUTHENTICATE_URL
    if me:
        base_url += '?' + urllib.parse.urlencode({
            'screen_name': me.split('/')[-1],
        })
    return oauth.authorization_url(base_url)


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

    if 'errors' in user_info:
        return {'error': 'Error fetching credentials %r' % user_info.get('errors')}
    
    user_id = user_info.get('id_str')
    username = user_info.get('screen_name')

    current_app.logger.debug('verified credentials. user_id=%s, username=%s', user_id, username)
    current_app.logger.debug('user_info: %r', user_info)
    
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

    def interpret_response(result):
        if result.status_code // 100 != 2:
            return util.wrap_silo_error_response(result)

        result_json = result.json()
        twitter_url = 'https://twitter.com/{}/status/{}'.format(
            result_json.get('user', {}).get('screen_name'),
            result_json.get('id_str'))
        return util.make_publish_success_response(twitter_url, result_json)

    def get_tweet_id(original):
        tweet_url = util.posse_post_discovery(original, TWEET_RE)
        if tweet_url:
            m = TWEET_RE.match(tweet_url)
            if m:
                return m.group(1), m.group(2)
        return None, None

    data = {}
    content = request.form.get('content[value]') or request.form.get('content')

    repost_of = request.form.get('repost-of')
    if repost_of:
        _, tweet_id = get_tweet_id(repost_of)
        if tweet_id:
            return interpret_response(
                requests.post(RETWEET_STATUS_URL.format(tweet_id), auth=auth))
        else:
            content = 'Reposted: {}'.format(repost_of)

    like_of = request.form.get('like-of')
    if like_of:
        _, tweet_id = get_tweet_id(like_of)
        if tweet_id:
            return interpret_response(
                requests.post(FAVE_STATUS_URL, data={
                    'id': tweet_id,
                }, auth=auth))
        else:
            content = 'Liked: {}'.format(like_of)

    if not content:
        return util.make_publish_error_response('Missing "content" property')

    in_reply_to = request.form.get('in-reply-to')
    if in_reply_to:
        twitterer, tweet_id = get_tweet_id(in_reply_to)
        if tweet_id:
            data['in_reply_to_status_id'] = tweet_id
            if (twitterer != site.account.username
                and '@' + twitterer not in content):
                content = '@{} {}'.format(twitterer, content)
        else:
            content = 'Re: {}, {}'.format(in_reply_to, content)

    location = request.form.get('location')
    current_app.logger.debug('received location param: %s', location)
    if location and location.startswith('geo:'):
        latlong = location[4:].split(';')[0].split(',', 1)
        if len(latlong) == 2:
            data['lat'], data['long'] = latlong

    target_length = 140
    permalink_url = request.form.get('url')
    photo_file = request.files.get('photo')
    if photo_file:
        target_length -= 23

    data['status'] = brevity.shorten(content, permalink=permalink_url,
                                     target_length=target_length)

    current_app.logger.debug('publishing with params %s', data)
    if photo_file:
        return interpret_response(
            requests.post(CREATE_WITH_MEDIA_URL, data=data,
                          files={'media[]': photo_file}, auth=auth))

    return interpret_response(
        requests.post(CREATE_STATUS_URL, data=data, auth=auth))
