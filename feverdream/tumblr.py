from feverdream import micropub
from feverdream import util
from feverdream.ext import db, redis
from feverdream.models import Account, Tumblr, Site
from flask import Blueprint, current_app, redirect, url_for, request, flash
from flask import make_response, session
from requests_oauthlib import OAuth1Session, OAuth1
import datetime
import html
import json
import requests
import sys
import uuid


REQUEST_TOKEN_URL = 'https://www.tumblr.com/oauth/request_token'
AUTHORIZE_URL = 'https://www.tumblr.com/oauth/authorize'
ACCESS_TOKEN_URL = 'https://www.tumblr.com/oauth/access_token'
USER_INFO_URL = 'https://api.tumblr.com/v2/user/info'
CREATE_POST_URL = 'https://api.tumblr.com/v2/blog/{}/post'
FETCH_POST_URL = 'https://api.tumblr.com/v2/blog/{}/posts'
SERVICE_NAME = 'tumblr'

tumblr = Blueprint('tumblr', __name__)


def get_auth_url(callback_uri):
    oauth = OAuth1Session(
        client_key=current_app.config['TUMBLR_CLIENT_KEY'],
        client_secret=current_app.config['TUMBLR_CLIENT_SECRET'],
        callback_uri=callback_uri)
    r = oauth.fetch_request_token(REQUEST_TOKEN_URL)
    session['oauth_token_secret'] = r.get('oauth_token_secret')
    return oauth.authorization_url(AUTHORIZE_URL)


def process_auth_callback():
    verifier = request.args.get('oauth_verifier')
    request_token = request.args.get('oauth_token')
    if not verifier or not request_token:
        # user declined
        return {'error': 'Tumblr authorization declined'}

    request_token_secret = session.get('oauth_token_secret')
    oauth = OAuth1Session(
        client_key=current_app.config['TUMBLR_CLIENT_KEY'],
        client_secret=current_app.config['TUMBLR_CLIENT_SECRET'],
        resource_owner_key=request_token,
        resource_owner_secret=request_token_secret)
    oauth.parse_authorization_response(request.url)
    # get the access token and secret
    r = oauth.fetch_access_token(ACCESS_TOKEN_URL)
    token = r.get('oauth_token')
    secret = r.get('oauth_token_secret')

    info_resp = oauth.get(USER_INFO_URL).json()
    user_info = info_resp.get('response', {}).get('user')
    user_id = username = user_info.get('name')

    return {
        'token': token,
        'secret': secret,
        'user_id': user_id,
        'username': username,
        'user_info': user_info,
    }


@tumblr.route('/tumblr/authorize', methods=['POST'])
def authorize():
    try:
        callback_uri = url_for('.callback', _external=True)
        return redirect(get_auth_url(callback_uri))
    except:
        current_app.logger.exception('Starting Tumblr authorization')
        flash(html.escape(str(sys.exc_info()[0])), 'danger')
        return redirect(url_for('views.index'))


@tumblr.route('/tumblr/callback')
def callback():
    try:
        result = process_auth_callback()
        if 'error' in result:
            flash(result['error'], category='danger')
            return redirect(url_for('views.index'))

        account = Account.query.filter_by(
            service='tumblr', user_id=result['user_id']).first()

        if not account:
            account = Account(service='tumblr', user_id=result['user_id'])
            db.session.add(account)

        account.username = result['username']
        account.user_info = result['user_info']
        account.token = result['token']
        account.token_secret = result['secret']

        account.sites = []
        for blog in result['user_info'].get('blogs', []):
            account.sites.append(Tumblr(
                url=blog.get('url'),
                domain=util.domain_for_url(blog.get('url')),
                site_id=blog.get('name'),
                site_info=blog))

        db.session.commit()
        flash('Authorized {}: {}'.format(account.username, ', '.join(
            s.domain for s in account.sites)))
        return redirect(url_for('views.account', service=SERVICE_NAME,
                                username=account.username))

    except:
        current_app.logger.exception('During Tumblr authorization callback')
        flash(html.escape(str(sys.exc_info()[0])), 'danger')
        return redirect(url_for('views.index'))


@tumblr.route('/tumblr/indieauth', methods=['GET', 'POST'])
def indieauth():
    if request.method == 'POST':
        return verify_indieauth()
    return do_indieauth()


def do_indieauth():
    try:
        me = request.args.get('me')
        redirect_uri = request.args.get('redirect_uri')
        site = Site.lookup_by_url(me)

        if not site:
            return redirect(util.set_query_params(
                redirect_uri, error='Authorization failed. Unknown site {}'
                .format(me)))

        session['indieauth_params'] = {
            'me': me,
            'redirect_uri': redirect_uri,
            'client_id': request.args.get('client_id'),
            'state': request.args.get('state', ''),
        }
        callback_uri = url_for('.indiecb', _external=True)
        return redirect(get_auth_url(callback_uri))

    except:
        current_app.logger.exception('Starting Tumblr indieauth')
        return redirect(util.set_query_params(
            redirect_uri, error=str(sys.exc_info()[0])))


def verify_indieauth():
    code = request.form.get('code')
    client_id = request.form.get('client_id')
    redirect_uri = request.form.get('redirect_uri')
    state = request.form.get('state', '')

    datastr = redis.get('indieauth-code:{}'.format(code))
    if not datastr:
        return util.urlenc_response(
            {'error': 'Unrecognized or expired authorization code'}, 400)

    data = json.loads(datastr.decode('utf-8'))
    for key, value in [('client_id', client_id),
                       ('redirect_uri', redirect_uri), ('state', state)]:
        if data.get(key) != value:
            return util.urlenc_response({'error': key + ' mismatch'}, 400)

    me = data.get('me')
    return util.urlenc_response({'me': me})


@tumblr.route('/tumblr/indiecb')
def indiecb():
    ia_params = session.get('indieauth_params', {})
    me = ia_params.get('me')
    client_id = ia_params.get('client_id')
    redirect_uri = ia_params.get('redirect_uri')
    state = ia_params.get('state', '')
    scope = ia_params.get('scope')

    result = process_auth_callback()
    if 'error' in result:
        return redirect(
            util.set_query_params(redirect_uri, error=result['error']))

    # check that the authorized user owns the requested site
    print('looking up site for user', me)
    my_site = Site.lookup_by_url(me)
    if not my_site:
        return redirect(util.set_query_params(
            redirect_uri,
            error='Authorization failed. Unknown site {}'.format(me)))

    authed_account = Account.query.filter_by(
        service='tumblr', user_id=result['user_id']).first()

    if not authed_account:
        return redirect(util.set_query_params(
            redirect_uri,
            error='Authorization failed. Unknown account {}'
            .format(result['user_id'])))

    if my_site.account != authed_account:
        return redirect(util.set_query_params(
            redirect_uri,
            error='Authorized account {} does not own requested site {}'
            .format(authed_account.username, my_site.domain)))

    # hand back a code to the micropub client
    code = uuid.uuid4().hex
    redis.setex('indieauth-code:{}'.format(code),
                datetime.timedelta(minutes=5),
                json.dumps({
                    'site': my_site.id,
                    'me': me,
                    'redirect_uri': redirect_uri,
                    'client_id': client_id,
                    'state': state,
                    'scope': scope,
                }))
    return redirect(util.set_query_params(
        redirect_uri, me=me, state=state, code=code))


@micropub.publisher(SERVICE_NAME)
def publish(site):
    auth = OAuth1(
        client_key=current_app.config['TUMBLR_CLIENT_KEY'],
        client_secret=current_app.config['TUMBLR_CLIENT_SECRET'],
        resource_owner_key=site.account.token,
        resource_owner_secret=site.account.token_secret)

    type = request.form.get('h')

    create_post_url = CREATE_POST_URL.format(site.domain)
    photo_file = request.files.get('photo')
    if photo_file:
        # tumblr signs multipart in a weird way. first sign the request as if
        # it's application/x-www-form-urlencoded, then recreate the request as
        # multipart but use the signed headers from before. Mostly cribbed from
        # https://github.com/tumblr/pytumblr/blob/\
        # 20e7e38ba6f0734335deee64d4cae45fa8a2ce90/pytumblr/request.py#L101

        # The API documentation and some of the code samples gave me the
        # impression that you could also send files just as part of the
        # form-encoded data but I couldnit make it work
        # https://www.tumblr.com/docs/en/api/v2#pphoto-posts
        # https://gist.github.com/codingjester/1649885#file-upload-php-L56
        data = util.trim_nulls({
            'type': 'photo',
            'slug': request.form.get('slug'),
            'caption': request.form.get('content') or request.form.get('name'),
        })
        fake_req = requests.Request('POST', create_post_url, data=data)
        fake_req = fake_req.prepare()
        auth(fake_req)

        real_headers = dict(fake_req.headers)

        # manually strip these, requests will recalculate them for us
        del real_headers['Content-Type']
        del real_headers['Content-Length']

        current_app.logger.info(
            'uploading photo to tumblr %s, headers=%r',
            create_post_url, real_headers)
        r = requests.post(create_post_url, data=data, files={
            'data': photo_file,
        }, headers=real_headers)

    else:
        data = util.trim_nulls({
            # one of: text, photo, quote, link, chat, audio, video
            'type': 'text',
            'slug': request.form.get('slug'),
            'title': request.form.get('name'),
            'body': micropub.get_complex_content(),
        })
        current_app.logger.info(
            'posting to tumblr %s, data=%r', create_post_url, data)
        r = requests.post(create_post_url, data=data, auth=auth)

    current_app.logger.info(
        'response from tumblr %r, data=%r, headers=%r',
        r, r.content, r.headers)

    if r.status_code // 100 != 2:
        current_app.logger.warn(
            'Tumblr publish failed with response %s', r.text)
        return r.text, r.status_code

    location = None
    if 'Location' in r.headers:
        location = r.headers['Location']
    else:
        # only get back the id, look up the url
        post_id = r.json().get('response').get('id')
        r = requests.get(FETCH_POST_URL.format(site.domain), params={
            'api_key': current_app.config['TUMBLR_CLIENT_KEY'],
            'id': post_id,
        })
        if r.status_code // 100 == 2:
            posts = r.json().get('response', {}).get('posts', [])
            if posts:
                location = posts[0].get('post_url')

    result = make_response('', 201)
    if location:
        result.headers['Location'] = location
    return result
