from feverdream import util
from feverdream.ext import db
from feverdream.models import Account, Blogger
from flask import Blueprint, url_for, current_app, request, redirect, flash
from flask import make_response
from flask.ext.wtf.csrf import generate_csrf, validate_csrf
import json
import requests
import urllib.parse


API_AUTH_URL = 'https://accounts.google.com/o/oauth2/auth'
API_TOKEN_URL = 'https://www.googleapis.com/oauth2/v3/token'
API_SELF_URL = 'https://www.googleapis.com/blogger/v3/users/self'
API_BLOGS_URL = 'https://www.googleapis.com/blogger/v3/users/self/blogs'
API_CREATE_POST_URL = 'https://www.googleapis.com/blogger/v3/blogs/{}/posts'

BLOGGER_SCOPE = 'https://www.googleapis.com/auth/blogger'
SERVICE_NAME = 'blogger'


blogger = Blueprint('blogger', __name__)


@blogger.route('/blogger/authorize', methods=['POST'])
def authorize():
    redirect_uri = url_for('.callback', _external=True)
    return redirect(get_authenticate_url(redirect_uri))


@blogger.route('/blogger/callback')
def callback():
    redirect_uri = url_for('.callback', _external=True)
    result = process_authenticate_callback(redirect_uri)

    if 'error' in result:
        flash(result['error'], category='danger')
        return redirect(url_for('views.index'))

    # find or create the account
    user_id = result['user_id']
    account = Account.query.filter_by(
        service=SERVICE_NAME, user_id=user_id).first()

    if not account:
        account = Account(service=SERVICE_NAME, user_id=user_id)
        db.session.add(account)

    account.username = result['username']
    account.user_info = result['user_info']
    account.token = result['token']

    r = requests.get(API_BLOGS_URL, headers={
        'Authorization': 'Bearer ' + account.token,
    })

    if util.check_request_failed(r):
        return redirect(url_for('views.index'))

    payload = r.json()
    blogs = payload.get('items', [])

    # find or create the sites
    account.sites = []
    for blog in blogs:
        account.sites.append(Blogger(
            url=blog.get('url'),
            domain=util.domain_for_url(blog.get('url')),
            site_id=blog.get('id'),
            site_info=blog))

    db.session.commit()
    flash('Authorized {}: {}'.format(account.username, ', '.join(
        s.domain for s in account.sites)))

    return redirect(url_for('views.account',
                            service=SERVICE_NAME,
                            username=account.username))


def get_authenticate_url(redirect_uri):
    csrf_token = generate_csrf()
    return API_AUTH_URL + '?' + urllib.parse.urlencode({
        'response_type': 'code',
        'client_id': current_app.config['GOOGLE_CLIENT_ID'],
        'redirect_uri': redirect_uri,
        'scope': BLOGGER_SCOPE,
        'state': csrf_token,
    })


def process_authenticate_callback(redirect_uri):
    code = request.args.get('code')
    error = request.args.get('error')

    if error:
        return {'error': 'Blogger authorization canceled or '
                'failed with error: {}' .format(error)}

    if not validate_csrf(request.args.get('state')):
        return {'error': 'csrf token mismatch in blogger callback.'}

    r = requests.post(API_TOKEN_URL, data={
        'code': code,
        'client_id': current_app.config['GOOGLE_CLIENT_ID'],
        'client_secret': current_app.config['GOOGLE_CLIENT_SECRET'],
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code',
    })

    if util.check_request_failed(r):
        return {'error': 'failed to validate access token'}

    payload = r.json()
    access_token = payload.get('access_token')
    expires_in = payload.get('expires_in')

    current_app.logger.info('Got Blogger access token: %s', access_token)

    r = requests.get(API_SELF_URL, headers={
        'Authorization': 'Bearer ' + access_token,
    })

    if util.check_request_failed(r):
        return {'error': 'failed to fetch {}'.format(API_SELF_URL)}

    payload = r.json()
    username = user_id = payload.get('id')

    return {
        'user_id': user_id,
        'username': username,
        'user_info': payload,
        'token': access_token,
    }


def publish(site):
    """
    Request:

    POST https://www.googleapis.com/blogger/v3/blogs/6561492933847572094/posts
    {
     "title": "This is a test, beautiful friend",
     "content": "This is some content with <i>html</i>!"
    }

    Response:

    200 OK
    {
     "kind": "blogger#post",
     "id": "8225907794810815386",
     "blog": {
      "id": "6561492933847572094"
     },
     "published": "2015-04-14T20:00:00-07:00",
     "updated": "2015-04-14T20:00:19-07:00",
     "etag": "\"Fgc6PVMaOxmEtPvQq0K7b_sZrRM/dGltZXN0YW1wOiAxNDI5MDY2ODE5MTYwCm9mZnNldDogLTI1MjAwMDAwCg\"",
     "url": "http://nofeathersnofur.blogspot.com/2015/04/this-is-test-beautiful-friend.html",
     "selfLink": "https://www.googleapis.com/blogger/v3/blogs/6561492933847572094/posts/8225907794810815386",
     "title": "This is a test, beautiful friend",
     "content": "This is some content with <i>html</i>!",
     "author": {
      "id": "01975554238474627641",
      "displayName": "Kyle",
      "url": "http://www.blogger.com/profile/01975554238474627641",
      "image": {
       "url": "http://img2.blogblog.com/img/b16-rounded.gif"
      }
     },
     "replies": {
      "totalItems": "0",
      "selfLink": "https://www.googleapis.com/blogger/v3/blogs/6561492933847572094/posts/8225907794810815386/comments"
     },
     "status": "LIVE",
     "readerComments": "ALLOW"
    }
    """
    type = request.form.get('h')
    create_post_url = API_CREATE_POST_URL.format(site.site_id)

    current_app.logger.info('posting to blogger %s', create_post_url)

    post_data = util.trim_nulls({
        'title': request.form.get('name'),
        'content': util.get_complex_content(request.form),
    })

    r = requests.post(create_post_url, headers={
        'Authorization': 'Bearer ' + site.account.token,
        'Content-Type': 'application/json',
    }, data=json.dumps(post_data))

    current_app.logger.info(
        'response from blogger %r, data=%r, headers=%r',
        r, r.content, r.headers)

    if r.status_code // 100 != 2:
        current_app.logger.error(
            'post to blogger failed! %s %s', r, r.text)
        return r.text, r.status_code

    resp = make_response('', 201)
    resp.headers['Location'] = r.json().get('url')
    return resp
