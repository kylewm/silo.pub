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
from silopub.models import Account, Flickr
from oauthlib.oauth1 import SIGNATURE_TYPE_BODY


SERVICE_NAME = 'flickr'

REQUEST_TOKEN_URL = 'https://www.flickr.com/services/oauth/request_token'
AUTHORIZE_URL = 'https://www.flickr.com/services/oauth/authorize'
AUTHENTICATE_URL = 'https://www.flickr.com/services/oauth/authenticate'
ACCESS_TOKEN_URL = 'https://www.flickr.com/services/oauth/access_token'
API_URL = 'https://api.flickr.com/services/rest'
UPLOAD_URL = 'https://up.flickr.com/services/upload'

FLICKR_PHOTO_RE = re.compile(
    r'https?://(?:www\.)?flickr.com/photos/([\w@]+)/(\d+)/?')
FLICKR_PERSON_RE = re.compile(
    r'https?://(?:www\.|)?flickr.com/(?:photos|people)/([\w@]+)/?')


flickr = Blueprint('flickr', __name__)


@flickr.route('/flickr.com/<nsid>')
def proxy_homepage(nsid):
    current_app.logger.debug('constructing proxy homepage with nsid: %s', nsid)
    account = Account.query.filter_by(
        service=SERVICE_NAME, user_id=nsid).first()

    if not account:
        abort(404)

    return util.render_proxy_homepage(account.sites[0], account.username)


@flickr.route('/flickr/authorize', methods=['POST'])
def authorize():
    try:
        callback_uri = url_for('.callback', _external=True)
        return redirect(get_authorize_url(callback_uri))
    except:
        current_app.logger.exception('Starting Flickr authorization')
        flash(html.escape(str(sys.exc_info()[0])), 'danger')
        return redirect(url_for('views.index'))


@flickr.route('/flickr/callback')
def callback():
    try:
        callback_uri = url_for('.callback', _external=True)
        result = process_authenticate_callback(callback_uri)
        if 'error' in result:
            flash(result['error'], category='danger')
            return redirect(url_for('views.index'))

        account = Account.query.filter_by(
            service=SERVICE_NAME, user_id=result['user_id']).first()

        if not account:
            account = Account(service=SERVICE_NAME, user_id=result['user_id'])
            db.session.add(account)

        account.username = result['username']
        account.user_info = result['user_info']
        account.token = result['token']
        account.token_secret = result['secret']

        account.sites = [Flickr(
            url='https://flickr.com/{}'.format(account.user_id),
            domain='flickr.com/{}'.format(account.user_id),
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
        client_key=current_app.config['FLICKR_CLIENT_KEY'],
        client_secret=current_app.config['FLICKR_CLIENT_SECRET'],
        callback_uri=callback_uri)
    r = oauth.fetch_request_token(REQUEST_TOKEN_URL)
    session['oauth_token_secret'] = r.get('oauth_token_secret')
    return oauth.authorization_url(AUTHENTICATE_URL)


def get_authorize_url(callback_uri):
    oauth = OAuth1Session(
        client_key=current_app.config['FLICKR_CLIENT_KEY'],
        client_secret=current_app.config['FLICKR_CLIENT_SECRET'],
        callback_uri=callback_uri)
    r = oauth.fetch_request_token(REQUEST_TOKEN_URL)
    session['oauth_token_secret'] = r.get('oauth_token_secret')
    return oauth.authorization_url(AUTHORIZE_URL, perms='write')


def process_authenticate_callback(callback_uri):
    verifier = request.args.get('oauth_verifier')
    request_token = request.args.get('oauth_token')
    if not verifier or not request_token:
        # user declined
        return {'error': 'Flickr authorization declined'}

    request_token_secret = session.get('oauth_token_secret')
    oauth = OAuth1Session(
        client_key=current_app.config['FLICKR_CLIENT_KEY'],
        client_secret=current_app.config['FLICKR_CLIENT_SECRET'],
        resource_owner_key=request_token,
        resource_owner_secret=request_token_secret)
    oauth.parse_authorization_response(request.url)
    # get the access token and secret
    r = oauth.fetch_access_token(ACCESS_TOKEN_URL)
    current_app.logger.debug('response from access token: %r', r)

    token = r.get('oauth_token')
    secret = r.get('oauth_token_secret')
    user_id = r.get('user_nsid')
    username = r.get('fullname')

    r = call_api_method('GET', 'flickr.people.getInfo', {
        'user_id': user_id
    }, token, secret)
    user_info = r.json()

    return {
        'token': token,
        'secret': secret,
        'user_id': user_id,
        'username': username,
        'user_info': user_info,
    }


def call_api_method(http_method, flickr_method, params,
                    token=None, secret=None, site=None):
    auth = OAuth1(
        client_key=current_app.config['FLICKR_CLIENT_KEY'],
        client_secret=current_app.config['FLICKR_CLIENT_SECRET'],
        resource_owner_key=token or site.token or site.account.token,
        resource_owner_secret=secret or site.token_secret
        or site.account.token_secret)

    full_params = {
        'nojsoncallback': 1,
        'format': 'json',
        'method': flickr_method,
    }
    full_params.update(params)
    return requests.request(http_method, API_URL, params=full_params,
                            auth=auth)


def upload(params, photo_file, token=None, secret=None, site=None):
    auth = OAuth1(
        client_key=current_app.config['FLICKR_CLIENT_KEY'],
        client_secret=current_app.config['FLICKR_CLIENT_SECRET'],
        resource_owner_key=token or site.token or site.account.token,
        resource_owner_secret=secret or site.token_secret
        or site.account.token_secret,
        signature_type=SIGNATURE_TYPE_BODY)

    # create a request without files for signing
    faux_req = requests.Request(
        'POST', UPLOAD_URL, data=params, auth=auth).prepare()
    # parse the signed parameters back out of the body
    data = urllib.parse.parse_qsl(faux_req.body)

    # and use them in the real request
    current_app.logger.debug('uploading with data: %s', data)
    resp = requests.post(UPLOAD_URL, data=data, files={
        'photo': photo_file,
    })
    current_app.logger.debug('upload response: %s, %s', resp, resp.text)
    return resp


def interpret_upload_response(resp):
    m = re.search('<rsp stat="(\w+)">', resp.text, re.DOTALL)
    if not m:
        return (None, 'Expected response with <rsp stat="...">. '
                'Got: %s' % resp.text)

    stat = m.group(1)
    if stat == 'fail':
        m = re.search('<err code="(\d+)" msg="([\w ]+)" />',
                      resp.text, re.DOTALL)
        if not m:
            return (None, 'Expected response with <err code="..." msg=".." />.'
                    ' Got: %s' % resp.text)
        return (None, 'Upstream error %d: %s' % (int(m.group(1)), m.group(2)))

    m = re.search('<photoid>(\d+)</photoid>', resp.text, re.DOTALL)
    if not m:
        return (None, 'Expected response with <photoid>...</photoid>. '
                'Got: %s' % resp.text)

    return m.group(1), None


def publish(site):
    in_reply_to = request.form.get('in-reply-to')
    like_of = request.form.get('like-of')

    title = request.form.get('name')
    desc = request.form.get('content[value]') or request.form.get('content')

    # try to comment on a photo
    if in_reply_to:
        m = FLICKR_PHOTO_RE.match(in_reply_to)
        if not m:
            return util.make_publish_error_response(
                'Could not find Flickr photo to comment on based on URL {}'
                .format(in_reply_to))

        photo_id = m.group(2)
        r = call_api_method('POST', 'flickr.photos.comments.addComment', {
            'photo_id': photo_id,
            'comment_text': desc or title,
        }, site=site)
        result = r.json()
        if result.get('stat') == 'fail':
            return util.wrap_silo_error_response(r)
        return util.make_publish_success_response(
            result.get('comment', {}).get('permalink'), result)

    # try to like a photo
    if like_of:
        m = FLICKR_PHOTO_RE.match(like_of)
        if not m:
            return util.make_publish_error_response(
                'Could not find Flickr photo to like based on URL {}'
                .format(in_reply_to))

        photo_id = m.group(2)
        r = call_api_method('POST', 'flickr.favorites.add', {
            'photo_id': photo_id,
        }, site=site)
        result = r.json()
        if result.get('stat') == 'fail':
            return util.wrap_silo_error_response(r)
        return util.make_publish_success_response(like_of, result)

    # otherwise we're uploading a photo
    photo_file = request.files.get('photo')
    if not photo_file:
        return util.make_publish_error_response('Missing "photo" attachment')

    r = upload({'title': title, 'description': desc}, photo_file,
               site=site)

    if r.status_code // 100 != 2:
      return util.wrap_silo_error_response(r)

    photo_id, error = interpret_upload_response(r)
    if error:
        return util.make_publish_error_response(error)

    # maybe add some tags or people
    cats = util.get_possible_array_value(request.form, 'category')
    tags = []
    user_ids = []

    for cat in cats:
        if util.looks_like_a_url(cat):
            resp = call_api_method(
                'GET', 'flickr.urls.lookupUser', {'url': cat}, site=site)
            if resp.status_code // 100 != 2:
                current_app.logger.error(
                    'Error looking up user by url %s. Response: %r, %s',
                    cat, resp, resp.text)
            result = resp.json()
            if result.get('stat') == 'fail':
                current_app.logger.debug(
                    'User not found for url %s', cat)
            else:
                user_id = result.get('user', {}).get('id')
                if user_id:
                    user_ids.append(user_id)
        else:
            tags.append('"' + cat + '"')

    if tags:
        current_app.logger.debug('Adding tags: %s', ','.join(tags))
        resp = call_api_method('POST', 'flickr.photos.addTags', {
            'photo_id': photo_id,
            'tags': ','.join(tags),
        }, site=site)
        current_app.logger.debug('Added tags: %r, %s', resp, resp.text)

    for user_id in user_ids:
        current_app.logger.debug('Tagging user id: %s', user_id)
        resp = call_api_method('POST', 'flickr.photos.people.add', {
            'photo_id': photo_id,
            'user_id': user_id,
        }, site=site)
        current_app.logger.debug('Tagged person: %r, %s', resp, resp.text)

    return util.make_publish_success_response(
        'https://www.flickr.com/photos/{}/{}/'.format(
            site.account.user_info.get('person', {}).get('path_alias')
            or site.account.user_id,
            photo_id))
